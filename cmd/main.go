package main

import (
	"archive/zip"
	"context"
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

type Config struct {
	FilePath   string    `toml:"FilePath"`
	Aws        AwsConfig `toml:"AWS"`
	Included   string    `toml:"Included"`
	DateFormat string    `toml:"DateFormat"`
}

type AwsConfig struct {
	BucketName      string `toml:"BUCKET_NAME"`
	AccessKeyId     string `toml:"ACCESS_KEY_ID"`
	SecretAccessKey string `toml:"SECRET_ACCESS_KEY"`
	Region          string `toml:"REGION"`
}

var (
	config Config
	files  []string
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

	if _, err := toml.Decode(string(data), &config); err != nil {
		slog.Error("Failed to parse config", "err", err)
		panic(err)
	}

	slog.Info("Config loaded",
		"FilePath", config.FilePath,
		"Region", config.Aws.Region,
		"Included", config.Included,
	)
}
func main() {
	err := filepath.WalkDir(config.FilePath, walk)
	if err != nil {
		slog.Error("Failed to walk directory", "err", err)
		return
	}
	if len(files) == 0 {
		slog.Error("No files found. Check your config.toml")
	}
	dateName := time.Now().Local().Format(config.DateFormat)
	zipName := dateName + ".zip"
	if err := createZip(files, config.FilePath, zipName); err != nil {
		slog.Error("Failed to create zip", "err", err)
		os.Exit(1)
	}
	slog.Info("Config archive created", "path", zipName)

	if err := uploadToS3(zipName, config.Aws); err != nil {
		slog.Error("Failed to upload to S3", "err", err)
		os.Exit(1)
	}

	slog.Info("Uploaded zip to S3", "bucket", config.Aws.BucketName, "key", zipName)

	err = os.Remove(zipName)
	if err != nil {
		slog.Error("Failed to clean up zip", "err", err)
		os.Exit(1)
	}
	slog.Info("Cleaned up zip file")
}

func walk(s string, _ fs.DirEntry, err error) error {
	matched, err := regexp.MatchString(config.Included, s)
	if err != nil {
		slog.Error("Error", "err", err)
		return err
	}
	if matched {
		files = append(files, s)
		return nil
	}
	return nil
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

		h, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		h.Name = archiveName
		if info.ModTime().IsZero() {
			h.Modified = time.Now()
		}
		h.Method = zip.Deflate

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
