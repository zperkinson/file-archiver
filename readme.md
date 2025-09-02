# File archiver

A simple archiver for backing up files to S3 via a whitelist.

## Setup
- Prior to running the app, you must configure your `config.toml`. You do not have to specify your AWS credentials in the `config.toml`, as it will pull from your `~/.aws/credentials` file if not specified. However, your bucket name **must** be specified.
- `go build cmd/main.go`
- Setup a cron or task schedule to run the app in the same folder as the config.toml (if applicable)

By default, the app will create a zip file following the following format: `YYYY-MM-DD.zip`. However, the date format can be customized in `config.toml`.
See [Go docs](<https://pkg.go.dev/time#Layout>) for examples.
