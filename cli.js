#!/usr/bin/env node

const path = require("path");

require("dotenv").config({
    path: path.join(__dirname, ".env")
});
const { program } = require("commander");
const chalk = require("chalk");
const ora = require("ora");
const fs = require("fs");
const { scanURL } = require("./utils/checker");

program
    .name("urlscan")
    .description("Cyber URL Scanner CLI")
    .version("1.0.0");

program
    .command("scan <target>")
    .option("-m, --multi", "Scan multiple targets (file input)")
    .option("-o, --output <file>", "Save result to file")
    .description("Scan URL(s)")
    .action(async function (target) {

        // ambil options dari context
        const options = this.opts();

        let targets = [];

        if (options.multi) {
            targets = loadTargets(target);
        } else {
            targets = [target];
        }

        console.log("TARGETS:", targets); // debug

        let results = [];

        for (const url of targets) {

            if (typeof url !== "string") {
                console.log("INVALID TARGET:", url);
                continue;
            }

            const spinner = ora(`Scanning ${url}...`).start();

            try {
                const result = await scanURL(url);

                spinner.succeed(`Done: ${url}`);

                printResult(result);
                results.push(result);

            } catch (err) {
                spinner.fail(`Failed: ${url}`);
                console.log(err.message);
            }
        }

        // save output
        if (options.output) {
            fs.writeFileSync(options.output, JSON.stringify(results, null, 2));
            console.log(chalk.green(`\nSaved to ${options.output}`));
        }

    });

// load multi targets
function loadTargets(filePath) {
    const data = fs.readFileSync(filePath, "utf-8");

    return data
        .split("\n")
        .map(t => t.trim())
        .filter(t => t.length > 0);
}

// print result
function printResult(result) {
    console.log(chalk.cyan("\n=== SCAN RESULT ==="));

    console.log("URL:", result?.url);
    console.log("IP:", result?.ip);
    console.log("SSL:", result?.ssl?.valid ? "Valid" : "Invalid");
    console.log("Risk:", result?.risk);

    console.log("\n--- VirusTotal ---");
    console.log(result?.virustotal);

    console.log("\n--- AbuseIPDB ---");
    console.log(result?.abuseipdb);
}

program.parse();