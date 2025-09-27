package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type RootConfig struct {
	DateFormat string    `toml:"DateFormat"`
	AWS        AwsConfig `toml:"AWS"`
	Paths      map[string]PathConfig
}

type PathConfig struct {
	FilePath        string `toml:"FilePath"`
	Included        string `toml:"Included"`
	BucketName      string `toml:"BUCKET_NAME"`
	AccessKeyId     string `toml:"ACCESS_KEY_ID"`
	SecretAccessKey string `toml:"SECRET_ACCESS_KEY"`
	Region          string `toml:"REGION"`
}

type AwsConfig struct {
	BucketName      string `toml:"BUCKET_NAME"`
	AccessKeyId     string `toml:"ACCESS_KEY_ID"`
	SecretAccessKey string `toml:"SECRET_ACCESS_KEY"`
	Region          string `toml:"REGION"`
}

var (
	config RootConfig
	hashes map[string]string
)

func init() {
	logPath := "archiver.log"
	f, ferr := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if ferr == nil {
		mw := io.MultiWriter(os.Stdout, f)
		h := slog.NewTextHandler(mw, &slog.HandlerOptions{Level: slog.LevelInfo})
		slog.SetDefault(slog.New(h))
	} else {
		h := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
		slog.SetDefault(slog.New(h))
		slog.Error("Failed to open log file, continuing with console logging", "err", ferr)
	}

	data, err := os.ReadFile("config.toml")
	if err != nil {
		slog.Error("Failed to read config file", "err", err)
		panic(err)
	}

	// Decode into primitives to support arbitrary subsections
	raw := map[string]toml.Primitive{}
	md, err := toml.Decode(string(data), &raw)
	if err != nil {
		slog.Error("Failed to parse config", "err", err)
		panic(err)
	}

	config.Paths = make(map[string]PathConfig)
	for k, prim := range raw {
		switch k {
		case "DateFormat":
			if err := md.PrimitiveDecode(prim, &config.DateFormat); err != nil {
				slog.Error("Failed to decode DateFormat", "err", err)
			}
		case "AWS":
			if err := md.PrimitiveDecode(prim, &config.AWS); err != nil {
				slog.Error("Failed to decode AWS block", "err", err)
			}
		default:
			var pc PathConfig
			if err := md.PrimitiveDecode(prim, &pc); err != nil {
				slog.Warn("Skipping unrecognized or invalid section", "section", k, "err", err)
				continue
			}
			config.Paths[k] = pc
		}
	}

	pathNames := make([]string, 0, len(config.Paths))
	for name := range config.Paths {
		pathNames = append(pathNames, name)
	}
	slog.Info("Config loaded", "paths", strings.Join(pathNames, ", "), "dateFormat", config.DateFormat, "hasGlobalAWS", config.AWS.Region != "" || config.AWS.AccessKeyId != "" || config.AWS.SecretAccessKey != "" || config.AWS.BucketName != "")
}
func init() {
	if _, err := os.Stat("hashes.json"); errors.Is(err, os.ErrNotExist) {
		slog.Info("Hashes file not found, creating new one")
		f, _ := os.Create("hashes.json")
		if f != nil {
			_, _ = f.WriteString("{}")
			f.Close()
		}
	}
	var data []byte
	data, _ = os.ReadFile("hashes.json")
	_ = json.Unmarshal(data, &hashes)

}
func main() {
	if len(config.Paths) == 0 {
		slog.Warn("No paths defined in config.toml")
		return
	}

	dateName := time.Now().Local().Format(config.DateFormat)
	for name, path := range config.Paths {
		slog.Info("Processing path", "name", name, "path", path.FilePath)
		files, err := collectFiles(path.FilePath, path.Included)
		if err != nil {
			slog.Error("Failed to walk directory", "path", name, "err", err)
			continue
		}
		if len(files) == 0 {
			slog.Warn("No files matched include pattern", "path", name, "included", path.Included)
			continue
		}

		zipName := dateName + ".zip"
		if err := createZip(files, path.FilePath, zipName); err != nil {
			slog.Error("Failed to create zip", "path", name, "err", err)
			continue
		}
		slog.Info("Config archive created", "path", name, "path", zipName)

		newHash, err := sha256File(zipName)
		if err != nil {
			slog.Error("Failed to compute sha256 for zip", "path", name, "err", err)
			_ = os.Remove(zipName)
			continue
		}

		if data, err := os.ReadFile("hashes.json"); err == nil && len(data) > 0 {
			_ = json.Unmarshal(data, &hashes)
		}
		if old, ok := hashes[name]; ok && strings.EqualFold(old, newHash) {
			slog.Info("No changes detected; skipping upload and hash update", "key", name)
			if err := os.Remove(zipName); err != nil {
				slog.Error("Failed to clean up zip", "path", name, "err", err)
			} else {
				slog.Info("Cleaned up zip file", "path", name)
			}
			continue
		}

		effectiveAWS := mergeAWS(config.AWS, path)
		if err := uploadToS3(zipName, effectiveAWS); err != nil {
			slog.Error("Failed to upload to S3. Deleting file", "path", name, "err", err)
			_ = os.Remove(zipName)
			continue
		}
		slog.Info("Uploaded zip to S3", "path", name, "bucket", effectiveAWS.BucketName, "key", zipName)

		if err := upsertHashJSON(name, newHash); err != nil {
			slog.Error("Failed to write hash to hashes.json", "path", name, "err", err)
		} else {
			slog.Info("Updated hashes.json", "key", name, "sha256", newHash)
		}

		if err := os.Remove(zipName); err != nil {
			slog.Error("Failed to clean up zip", "path", name, "err", err)
			continue
		}
		slog.Info("Cleaned up zip file", "path", name)
	}
}

func collectFiles(basePath, includePattern string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(basePath, func(s string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		matched, err := regexp.MatchString(includePattern, s)
		if err != nil {
			return err
		}
		if matched {
			files = append(files, s)
		}
		return nil
	})
	return files, err
}

func mergeAWS(global AwsConfig, path PathConfig) AwsConfig {
	res := global
	if path.BucketName != "" {
		res.BucketName = path.BucketName
	}
	if path.AccessKeyId != "" {
		res.AccessKeyId = path.AccessKeyId
	}
	if path.SecretAccessKey != "" {
		res.SecretAccessKey = path.SecretAccessKey
	}
	if path.Region != "" {
		res.Region = path.Region
	}
	return res
}

func uploadToS3(zipPath string, awsCfg AwsConfig) error {
	if awsCfg.BucketName == "" {
		slog.Error("Bucket name is required")
		return errors.New("bucket name is required")
	}
	var cfg aws.Config
	var err error
	if awsCfg.Region == "" || awsCfg.AccessKeyId == "" || awsCfg.SecretAccessKey == "" {
		slog.Warn("Could not find any provided credentials, using system default")
		cfg, err = awsconfig.LoadDefaultConfig(
			ctxWithTimeout(),
		)
	} else {
		slog.Info("Using provided AWS credentials")
		cfg, err = awsconfig.LoadDefaultConfig(
			ctxWithTimeout(),
			awsconfig.WithRegion(awsCfg.Region),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(awsCfg.AccessKeyId, awsCfg.SecretAccessKey, "")),
		)
	}

	if err != nil {
		slog.Error("Error creating AWS config", "err", err)
		return err
	}

	client := s3.NewFromConfig(cfg)

	file, err := os.Open(zipPath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	_, err = client.PutObject(ctxWithTimeout(), &s3.PutObjectInput{
		Bucket:        &awsCfg.BucketName,
		Key:           &zipPath,
		Body:          file,
		ContentType:   aws.String("application/zip"),
		ContentLength: aws.Int64(info.Size()),
	})
	return err
}

func ctxWithTimeout() context.Context {
	ctx, _ := context.WithTimeout(context.Background(), 60*time.Second)
	return ctx
}

// sha256File computes the SHA-256 of the given file and returns it as lowercase hex string.
func sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// upsertHashJSON updates hashes.json with the provided key (e.g., path name) mapped to the given hash.
func upsertHashJSON(key, hash string) error {
	// Load existing map (if any)
	m := map[string]string{}
	if data, err := os.ReadFile("hashes.json"); err == nil && len(data) > 0 {
		_ = json.Unmarshal(data, &m)
	}

	m[key] = hash

	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("hashes.json", b, 0644)
}

func createZip(filePaths []string, baseDir, outPath string) error {
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	for _, p := range filePaths {
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		if info.IsDir() {
			continue
		}

		rel := p
		if baseDir != "" {
			if r, err := filepath.Rel(baseDir, p); err == nil {
				rel = r
			}
		}
		archiveName := filepath.ToSlash(rel)
		if strings.HasPrefix(archiveName, "./") {
			archiveName = archiveName[2:]
		}

		h := &zip.FileHeader{
			Name:   archiveName,
			Method: zip.Deflate,
		}

		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}

		src, err := os.Open(p)
		if err != nil {
			return err
		}
		if _, err := io.Copy(w, src); err != nil {
			src.Close()
			return err
		}
		src.Close()
	}
	return nil
}
