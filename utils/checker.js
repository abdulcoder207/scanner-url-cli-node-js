// require("dotenv").config();
const axios = require("axios");
const axiosVT = require("axios");
const dns = require("dns").promises;
const tls = require("tls");
const { URL } = require("url");


async function checkAbuseIP(ip) {
    console.log("CHECK ABUSE DIPANGGIL:", ip);
    const apiKey = process.env.ABUSE_API_KEY;

    try {
        const res = await axios.get(
            "https://api.abuseipdb.com/api/v2/check",
            {
                params: {
                    ipAddress: ip,
                    maxAgeInDays: 90
                },
                headers: {
                    Key: apiKey,
                    Accept: "application/json"
                }
            }
        );

        const data = res.data.data;

        return {
            ip: data.ipAddress,
            abuseScore: data.abuseConfidenceScore,
            country: data.countryCode,
            isp: data.isp,
            totalReports: data.totalReports
        };

    } catch (err) {
        console.log("ABUSE ERROR:", err.response?.data || err.message);

        return {
            error: "AbuseIPDB gagal",
            detail: err.response?.data || err.message
        };
    }
}
function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function checkVirusTotal(url) {
    const apiKey = process.env.VT_API_KEY;

    try {
        const submit = await axios.post(
            "https://www.virustotal.com/api/v3/urls",
            new URLSearchParams({ url }),
            {
                headers: {
                    "x-apikey": apiKey,
                    "Content-Type": "application/x-www-form-urlencoded"
                }
            }
        );

        const analysisId = submit.data.data.id;

        // ⏳ tunggu hasil scan
        await delay(3000);

        const result = await axios.get(
            `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
            {
                headers: { "x-apikey": apiKey }
            }
        );

        const stats = result.data.data.attributes.stats;

        return stats;

    } catch (err) {
        console.log("ERROR VT:", err.response?.data || err.message);
        return { error: "VirusTotal gagal diakses" };
    }
}

// VALIDASI URL
function isValidURL(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

// DETEKSI PHISHING LEBIH DALAM
function detectPhishing(url) {
    let warnings = [];

    if (/https?:\/\/\d+\.\d+\.\d+\.\d+/.test(url)) {
        warnings.push("Menggunakan IP address");
    }

    if (url.length > 10000) {
        warnings.push("URL terlalu panjang");
    }

    if (/bit\.ly|tinyurl|t\.co/.test(url)) {
        warnings.push("Menggunakan shortener");
    }

    if (url.includes("@")) {
        warnings.push("URL mengandung '@' (phishing trick)");
    }

    if ((url.match(/\./g) || []).length > 5) {
        warnings.push("Terlalu banyak subdomain");
    }

    return warnings;
}

// DNS LOOKUP
async function getDNSInfo(hostname) {
    try {
        const res = await dns.lookup(hostname);
        return res.address;
    } catch (err) {
        console.log("DNS ERROR:", err.message);
        return null;
    }
}

// SSL CHECK
function checkSSL(hostname) {
    return new Promise((resolve) => {
        const socket = tls.connect(443, hostname, { servername: hostname }, () => {
            const cert = socket.getPeerCertificate();
            resolve({
                valid: true,
                issuer: cert.issuer.O,
                valid_from: cert.valid_from,
                valid_to: cert.valid_to
            });
            socket.end();
        });

        socket.on("error", () => {
            resolve({ valid: false });
        });
    });
}

// REDIRECT TRACKER
async function trackRedirect(url) {
    let redirects = [];

    try {
        await axios.get(url, {
            maxRedirects: 5,
            validateStatus: null
        }).then(res => {
            if (res.request._redirectable._redirectCount > 0) {
                redirects = res.request._redirectable._redirects;
            }
        });
    } catch { }

    return redirects;
}

// RISK SCORING
function calculateRisk(warnings, sslValid) {
    let score = 0;

    score += warnings.length * 20;
    if (!sslValid) score += 30;

    if (score >= 60) return "high";
    if (score >= 30) return "medium";
    return "low";
}

// MAIN FUNCTION
async function scanURL(url) {

    // cek api key
    function checkApiKeys() {
        if (!process.env.VT_API_KEY) {
            console.log("❌ VirusTotal API key belum diisi");
        }

        if (!process.env.ABUSE_API_KEY) {
            console.log("❌ AbuseIPDB API key belum diisi");
        }
    }
    if (!isValidURL(url)) {
        return { status: "invalid URL" };
    }

    const parsed = new URL(url);
    const hostname = parsed.hostname;

    // console.log("IP RESULT: ", ip)
    const vt = await checkVirusTotal(url);
    const warnings = detectPhishing(url);
    const ip = await getDNSInfo(hostname);
    const abuse = await checkAbuseIP(ip);
    const ssl = await checkSSL(hostname);
    const redirects = await trackRedirect(url);

    let responseData = {};

    try {
        const res = await axios.get(url, { timeout: 10000 });

        responseData = {
            status_code: res.status,
            server: res.headers["server"] || "unknown",
            content_type: res.headers["content-type"]
        };
    } catch {
        responseData = {
            error: "Tidak bisa diakses"
        };
    }

    const risk = calculateRisk(warnings, ssl.valid);

    return {
        url,
        hostname,
        ip,
        ssl,
        redirects,
        response: responseData,
        warnings,
        risk,
        virustotal: vt,
        abuseipdb: abuse
    };
}

module.exports = { scanURL };