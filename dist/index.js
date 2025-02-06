/******/ var __webpack_modules__ = ({

/***/ 859:
/***/ ((module) => {

module.exports = eval("require")("@actions/core");


/***/ }),

/***/ 577:
/***/ ((module) => {

module.exports = eval("require")("@actions/exec");


/***/ })

/******/ });
/************************************************************************/
/******/ // The module cache
/******/ var __webpack_module_cache__ = {};
/******/ 
/******/ // The require function
/******/ function __nccwpck_require__(moduleId) {
/******/ 	// Check if module is in cache
/******/ 	var cachedModule = __webpack_module_cache__[moduleId];
/******/ 	if (cachedModule !== undefined) {
/******/ 		return cachedModule.exports;
/******/ 	}
/******/ 	// Create a new module (and put it into the cache)
/******/ 	var module = __webpack_module_cache__[moduleId] = {
/******/ 		// no module.id needed
/******/ 		// no module.loaded needed
/******/ 		exports: {}
/******/ 	};
/******/ 
/******/ 	// Execute the module function
/******/ 	var threw = true;
/******/ 	try {
/******/ 		__webpack_modules__[moduleId](module, module.exports, __nccwpck_require__);
/******/ 		threw = false;
/******/ 	} finally {
/******/ 		if(threw) delete __webpack_module_cache__[moduleId];
/******/ 	}
/******/ 
/******/ 	// Return the exports of the module
/******/ 	return module.exports;
/******/ }
/******/ 
/************************************************************************/
/******/ /* webpack/runtime/compat */
/******/ 
/******/ if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = new URL('.', import.meta.url).pathname.slice(import.meta.url.match(/^file:\/\/\/\w:/) ? 1 : 0, -1) + "/";
/******/ 
/************************************************************************/
var __webpack_exports__ = {};
/* harmony import */ var _actions_core__WEBPACK_IMPORTED_MODULE_0__ = __nccwpck_require__(859);
/* harmony import */ var _actions_exec__WEBPACK_IMPORTED_MODULE_1__ = __nccwpck_require__(577);



(async () => {
    try {
        // Inputs
        const image = _actions_core__WEBPACK_IMPORTED_MODULE_0__.getInput('image');
        const labels = _actions_core__WEBPACK_IMPORTED_MODULE_0__.getInput('labels');
        const policy = _actions_core__WEBPACK_IMPORTED_MODULE_0__.getInput('policy');
        const server = _actions_core__WEBPACK_IMPORTED_MODULE_0__.getInput('server');
        const token = _actions_core__WEBPACK_IMPORTED_MODULE_0__.getInput('token');
        const cfClientID = _actions_core__WEBPACK_IMPORTED_MODULE_0__.getInput('cf_client_id');
        const cfClientSecret = _actions_core__WEBPACK_IMPORTED_MODULE_0__.getInput('cf_client_secret');
        const scanIdInput = _actions_core__WEBPACK_IMPORTED_MODULE_0__.getInput('scan_id');
        const interval = parseInt(_actions_core__WEBPACK_IMPORTED_MODULE_0__.getInput('interval') || '10', 10);
        const retries = parseInt(_actions_core__WEBPACK_IMPORTED_MODULE_0__.getInput('retries') || '10', 10);
        const gokakashiVersion = _actions_core__WEBPACK_IMPORTED_MODULE_0__.getInput('gokakashi_version') || 'latest';

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
        _actions_core__WEBPACK_IMPORTED_MODULE_0__.info(`Pulling gokakashi binary version: ${gokakashiVersion}`);
        await _actions_exec__WEBPACK_IMPORTED_MODULE_1__.exec(`wget https://github.com/shinobistack/gokakashi/releases/download/${gokakashiVersion}/gokakashi-linux-amd64 -O gokakashi`);
        await _actions_exec__WEBPACK_IMPORTED_MODULE_1__.exec('chmod +x gokakashi');

        // Install Trivy
        await _actions_exec__WEBPACK_IMPORTED_MODULE_1__.exec(`wget -q https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh -O install_trivy.sh`);
        await _actions_exec__WEBPACK_IMPORTED_MODULE_1__.exec('chmod +x install_trivy.sh');
        await _actions_exec__WEBPACK_IMPORTED_MODULE_1__.exec(`./install_trivy.sh -b ${process.cwd()} v0.58.1`);
        await _actions_exec__WEBPACK_IMPORTED_MODULE_1__.exec('rm install_trivy.sh');
        await _actions_exec__WEBPACK_IMPORTED_MODULE_1__.exec(`chmod +x ${process.cwd()}/trivy`);
        process.env.PATH = `${process.cwd()}:${process.env.PATH}`;

        _actions_core__WEBPACK_IMPORTED_MODULE_0__.info(`Updated PATH: ${process.env.PATH}`);
        await _actions_exec__WEBPACK_IMPORTED_MODULE_1__.exec('./trivy --version');

        // Trigger an image scan
        let scanId = scanIdInput;
        if (!scanId) {
            _actions_core__WEBPACK_IMPORTED_MODULE_0__.info(`Triggering scan for image: ${image} with policy: ${policy}`);
            let scanOutput = '', scanError = '';

            await _actions_exec__WEBPACK_IMPORTED_MODULE_1__.exec('./gokakashi', [
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
            _actions_core__WEBPACK_IMPORTED_MODULE_0__.info(`Captured full scan output:\n${fullOutput}`);

            const match = fullOutput.match(/Scan ID:\s*([\w-]+)/i);
            if (!match) {
                throw new Error('Failed to extract Scan ID.');
            }
            scanId = match[1].trim();
        }

        _actions_core__WEBPACK_IMPORTED_MODULE_0__.info('Starting gokakashi agent...');
        await _actions_exec__WEBPACK_IMPORTED_MODULE_1__.exec('./gokakashi agent start', [
            `--server=${server}`,
            `--token=${token}`,
            `--labels=${labels}`,
            '--single-strike'
        ]);

        const scanUrl = `${server}/api/v1/scans/${scanId}`;
        _actions_core__WEBPACK_IMPORTED_MODULE_0__.info(`Scan details available at: ${scanUrl}`);

        // Poll scan status
        let status = '';
        for (let attempt = 1; attempt <= retries; attempt++) {
            _actions_core__WEBPACK_IMPORTED_MODULE_0__.info(`Checking scan status (Attempt ${attempt}/${retries})...`);

            const startTime = Date.now();
            const execOutput = await _actions_exec__WEBPACK_IMPORTED_MODULE_1__.getExecOutput('./gokakashi scan status', [
                `--scanID=${scanId}`,
                `--server=${server}`,
                `--token=${token}`,
            ]);

            const fullResponse = execOutput.stdout + execOutput.stderr;
            _actions_core__WEBPACK_IMPORTED_MODULE_0__.info(`Full scan response: ${fullResponse}`);

            const statusMatch = fullResponse.match(/Scan status:\s*([\w-]+)/i);
            if (statusMatch) {
                status = statusMatch[1].trim();
            } else {
                _actions_core__WEBPACK_IMPORTED_MODULE_0__.warning('Failed to parse scan status. Retrying...');
                continue;
            }

            if (["notify_pending", "notify_in_progress", "success"].includes(status)) {
                _actions_core__WEBPACK_IMPORTED_MODULE_0__.info(`Scan completed successfully with status: ${status}`);
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

        _actions_core__WEBPACK_IMPORTED_MODULE_0__.setOutput('report_url', scanUrl);
    } catch (error) {
        _actions_core__WEBPACK_IMPORTED_MODULE_0__.setFailed(error.message);
    }
})();

