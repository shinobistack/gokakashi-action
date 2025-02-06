# GoKakashi Scan Action

The goKakashi GitHub Action allows you to integrate container image vulnerability scans directly into your CI/CD workflows. It leverages the goKakashi API to trigger scans, monitor their progress, and fail the build if vulnerabilities exceed defined thresholds.

## Features

- Trigger scans for container images based on policies defined in your goKakashi configuration. 
- Monitor scan progress with retry and interval settings.
- Fetch and output scan reports as part of your CI/CD pipeline.
- Supports integration with Cloudflare Access headers for secured API access.

## Inputs

| Input Name         | Description                                                                | Required | Default     |
|--------------------|----------------------------------------------------------------------------|----------|-------------|
| `image`            | The container image to scan.                                              | Yes      | None        |
| `policy`           | The policy to use for scanning.                                           | Yes      | None        |
| `server`           | The URL of the goKakashi API server.                                      | Yes      | None        |
| `token`            | Authentication token for the goKakashi server.                           | Yes      | None        |
| `cf_client_id`     | Cloudflare Access Client ID (optional).                                   | No       | None        |
| `cf_client_secret` | Cloudflare Access Client Secret (optional).                               | No       | None        |
| `interval`         | Interval in seconds to check the scan status.                             | No       | `10`        |
| `retries`          | Number of retries before marking the scan as failed.                      | No       | `10`        |
| `gokakashi_version`| The version of goKakashi to use (e.g., `v0.1.0`, `latest`).               | No       | `v0.1.0`    |

---

## Outputs

| Output Name  | Description                          |
|--------------|--------------------------------------|
| `report_url` | URL of the scan report for the image.|


## Usage

Here's a basic example of how to use this action in your workflow: user.yaml


## Security

Please ensure that you store sensitive information like API tokens and Cloudflare Access credentials as [GitHub Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets).

## Error

The action will fail if:
- No scan_id is generated or provided.
- Scan status is error or does not complete successfully within the retry limit.
- Vulnerabilities exceed defined thresholds.

## Contributing

Contributions to improve the GoKakashi Scan Action are welcome. Please feel free to submit issues or pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## Support

This action is maintained by the GoKakashi team. For questions or support, please open an issue in the GitHub repository.
