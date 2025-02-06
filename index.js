import * as core from '@actions/core';
import * as exec from '@actions/exec';

(async () => {
    try {
        // Inputs
        const image = core.getInput('image');
        const labels = core.getInput('labels');
        const policy = core.getInput('policy');
        const server = core.getInput('server');
        const token = core.getInput('token');
        const cfClientID = core.getInput('cf_client_id');
        const cfClientSecret = core.getInput('cf_client_secret');
        const scanIdInput = core.getInput('scan_id');
        const interval = parseInt(core.getInput('interval') || '10', 10);
        const retries = parseInt(core.getInput('retries') || '10', 10);
        const gokakashiVersion = core.getInput('gokakashi_version') || 'latest';

        if (!Number.isInteger(interval) || interval <= 0) {
            throw new Error('Invalid interval. It must be a positive integer.');
        }
        if (!Number.isInteger(retries) || retries <= 0) {
            throw new Error('Invalid retries. It must be a positive integer.');
        }

        // Export Cloudflare Tokens as environment variables
        process.env.CF_ACCESS_CLIENT_ID = cfClientID;
        process.env.CF_ACCESS_CLIENT_SECRET = cfClientSecret;

        // Pull gokakashi binary
        core.info(`Pulling gokakashi binary version: ${gokakashiVersion}`);
        await exec.exec(`wget https://github.com/shinobistack/gokakashi/releases/download/${gokakashiVersion}/gokakashi-linux-amd64 -O gokakashi`);
        await exec.exec('chmod +x gokakashi');

        // Install Trivy
        await exec.exec(`wget -q https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh -O install_trivy.sh`);
        await exec.exec('chmod +x install_trivy.sh');
        await exec.exec(`./install_trivy.sh -b ${process.cwd()} v0.58.1`);
        await exec.exec('rm install_trivy.sh');
        await exec.exec(`chmod +x ${process.cwd()}/trivy`);
        process.env.PATH = `${process.cwd()}:${process.env.PATH}`;

        core.info(`Updated PATH: ${process.env.PATH}`);
        await exec.exec('./trivy --version');

        // Trigger an image scan
        let scanId = scanIdInput;
        if (!scanId) {
            core.info(`Triggering scan for image: ${image} with policy: ${policy}`);
            let scanOutput = '', scanError = '';

            await exec.exec('./gokakashi', [
                'scan', 'image',
                `--image=${image}`,
                `--policy=${policy}`,
                `--server=${server}`,
                `--token=${token}`,
                `--labels=${labels}`
            ], {
                listeners: {
                    stdout: (data) => {
                        scanOutput += data.toString();
                    },
                    stderr: (data) => {
                        scanError += data.toString();
                    }
                }
            });

            const fullOutput = scanOutput + '\n' + scanError;
            core.info(`Captured full scan output:\n${fullOutput}`);

            const match = fullOutput.match(/Scan ID:\s*([\w-]+)/i);
            if (!match) {
                throw new Error('Failed to extract Scan ID.');
            }
            scanId = match[1].trim();
        }

        core.info('Starting gokakashi agent...');
        await exec.exec('./gokakashi agent start', [
            `--server=${server}`,
            `--token=${token}`,
            `--labels=${labels}`,
            '--single-strike'
        ]);

        const scanUrl = `${server}/api/v1/scans/${scanId}`;
        core.info(`Scan details available at: ${scanUrl}`);

        // Poll scan status
        let status = '';
        for (let attempt = 1; attempt <= retries; attempt++) {
            core.info(`Checking scan status (Attempt ${attempt}/${retries})...`);

            const startTime = Date.now();
            const execOutput = await exec.getExecOutput('./gokakashi scan status', [
                `--scanID=${scanId}`,
                `--server=${server}`,
                `--token=${token}`,
            ]);

            const fullResponse = execOutput.stdout + execOutput.stderr;
            core.info(`Full scan response: ${fullResponse}`);

            const statusMatch = fullResponse.match(/Scan status:\s*([\w-]+)/i);
            if (statusMatch) {
                status = statusMatch[1].trim();
            } else {
                core.warning('Failed to parse scan status. Retrying...');
                continue;
            }

            if (["notify_pending", "notify_in_progress", "success"].includes(status)) {
                core.info(`Scan completed successfully with status: ${status}`);
                break;
            } else if (status === 'error') {
                throw new Error('Scan failed. Check logs for details.');
            }

            if (attempt < retries) {
                await new Promise(resolve => setTimeout(resolve, Math.max(0, interval * 1000 - (Date.now() - startTime))));
            }
        }

        if (!status || !["notify_pending", "notify_in_progress", "success"].includes(status)) {
            throw new Error(`Scan failed to complete successfully. Last known status: ${status}`);
        }

        core.setOutput('report_url', scanUrl);
    } catch (error) {
        core.setFailed(error.message);
    }
})();
