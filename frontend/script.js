/* =========================================================
   NEON GUARD
   Frontend Application Logic
   ========================================================= */


/* =========================================================
   DOM ELEMENTS
   ========================================================= */

const senderInput = document.getElementById("sender");
const subjectInput = document.getElementById("subject");
const bodyInput = document.getElementById("body");

const characterCount = document.getElementById("character-count");

const analyzeButton = document.getElementById("analyze-button");

const scanningPanel = document.getElementById("scanning-panel");
const scannerProgressBar = document.getElementById(
    "scanner-progress-bar"
);

const errorPanel = document.getElementById("error-panel");
const errorMessage = document.getElementById("error-message");

const resultsPanel = document.getElementById("results-panel");

const riskScore = document.getElementById("risk-score");
const scoreRingValue = document.getElementById(
    "score-ring-value"
);

const riskLevel = document.getElementById("risk-level");
const classification = document.getElementById(
    "classification"
);

const contentScore = document.getElementById("content-score");
const contentBar = document.getElementById("content-bar");
const contentSummary = document.getElementById(
    "content-summary"
);

const senderScore = document.getElementById("sender-score");
const senderBar = document.getElementById("sender-bar");
const senderSummary = document.getElementById(
    "sender-summary"
);

const urlScore = document.getElementById("url-score");
const urlBar = document.getElementById("url-bar");
const urlSummary = document.getElementById(
    "url-summary"
);

const threatIndicators = document.getElementById(
    "threat-indicators"
);

const securityAssessment = document.getElementById(
    "security-assessment"
);

const recommendations = document.getElementById(
    "recommendations"
);

const newAnalysisButton = document.getElementById(
    "new-analysis-button"
);


/* =========================================================
   CONSTANTS
   ========================================================= */

const MAX_BODY_LENGTH = 100000;

const ANALYZE_ENDPOINT = "/api/analyze";

const RISK_CLASS_NAMES = [
    "risk-safe",
    "risk-low",
    "risk-suspicious",
    "risk-high",
    "risk-critical",
];


/* =========================================================
   INITIALIZATION
   ========================================================= */

document.addEventListener("DOMContentLoaded", () => {
    updateCharacterCount();
    setupEventListeners();
});


/* =========================================================
   EVENT LISTENERS
   ========================================================= */

function setupEventListeners() {

    bodyInput.addEventListener(
        "input",
        updateCharacterCount
    );

    analyzeButton.addEventListener(
        "click",
        handleAnalysis
    );

    newAnalysisButton.addEventListener(
        "click",
        resetApplication
    );

    senderInput.addEventListener(
        "keydown",
        handleEnterKey
    );

    subjectInput.addEventListener(
        "keydown",
        handleEnterKey
    );
}


/* =========================================================
   ENTER KEY HANDLER
   ========================================================= */

function handleEnterKey(event) {

    if (
        event.key === "Enter" &&
        !event.shiftKey
    ) {
        event.preventDefault();

        handleAnalysis();
    }
}


/* =========================================================
   CHARACTER COUNT
   ========================================================= */

function updateCharacterCount() {

    const length = bodyInput.value.length;

    characterCount.textContent =
        `${length.toLocaleString()} characters`;

    if (length > MAX_BODY_LENGTH) {

        characterCount.textContent =
            `${length.toLocaleString()} / ${MAX_BODY_LENGTH.toLocaleString()} characters`;

        characterCount.style.color =
            "var(--red)";

    } else {

        characterCount.style.color =
            "";
    }
}


/* =========================================================
   MAIN ANALYSIS HANDLER
   ========================================================= */

async function handleAnalysis() {

    hideError();

    const sender = senderInput.value.trim();
    const subject = subjectInput.value.trim();
    const body = bodyInput.value.trim();

    const validationError =
        validateInputs(
            sender,
            subject,
            body
        );

    if (validationError) {

        showError(validationError);

        return;
    }

    setAnalyzingState(true);

    try {

        await runScannerAnimation();

        const result = await sendAnalysisRequest({
            sender,
            subject,
            body
        });

        if (!result.success) {

            throw new Error(
                result.message ||
                result.error ||
                "Unable to analyze the email."
            );
        }

        renderResults(result);

    } catch (error) {

        console.error(
            "NEON GUARD analysis error:",
            error
        );

        showError(
            error.message ||
            "An unexpected error occurred during analysis."
        );

    } finally {

        setAnalyzingState(false);
    }
}


/* =========================================================
   INPUT VALIDATION
   ========================================================= */

function validateInputs(
    sender,
    subject,
    body
) {

    if (!sender) {
        return "Please enter the sender email address.";
    }

    if (!isValidEmail(sender)) {
        return "Please enter a valid sender email address.";
    }

    if (!subject) {
        return "Please enter the email subject.";
    }

    if (!body) {
        return "Please paste or enter the email body.";
    }

    if (body.length > MAX_BODY_LENGTH) {

        return (
            "The email body exceeds the maximum allowed size."
        );
    }

    return null;
}


/* =========================================================
   EMAIL VALIDATION
   ========================================================= */

function isValidEmail(email) {

    const emailPattern =
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    return emailPattern.test(email);
}


/* =========================================================
   SEND REQUEST TO FLASK
   ========================================================= */

async function sendAnalysisRequest(data) {

    const response = await fetch(
        ANALYZE_ENDPOINT,
        {
            method: "POST",

            headers: {
                "Content-Type": "application/json",
            },

            body: JSON.stringify(data),
        }
    );

    let result;

    try {

        result = await response.json();

    } catch (error) {

        throw new Error(
            "The server returned an invalid response."
        );
    }

    if (!response.ok) {

        throw new Error(
            result.message ||
            result.error ||
            `Server error (${response.status}).`
        );
    }

    return result;
}


/* =========================================================
   SCANNING STATE
   ========================================================= */

function setAnalyzingState(isAnalyzing) {

    analyzeButton.disabled = isAnalyzing;

    if (isAnalyzing) {

        analyzeButton.querySelector(
            "span:last-child"
        ).textContent = "ANALYZING...";

        scanningPanel.classList.remove("hidden");

        resultsPanel.classList.add("hidden");

        scannerProgressBar.style.width = "0%";

    } else {

        analyzeButton.querySelector(
            "span:last-child"
        ).textContent = "ANALYZE EMAIL";
    }
}


/* =========================================================
   SCANNER ANIMATION
   ========================================================= */

function runScannerAnimation() {

    return new Promise((resolve) => {

        let progress = 0;

        const interval = setInterval(() => {

            progress += Math.floor(
                Math.random() * 9
            ) + 4;

            if (progress >= 100) {

                progress = 100;

                scannerProgressBar.style.width =
                    `${progress}%`;

                clearInterval(interval);

                setTimeout(() => {
                    resolve();
                }, 250);

                return;
            }

            scannerProgressBar.style.width =
                `${progress}%`;

        }, 100);
    });
}


/* =========================================================
   RENDER COMPLETE RESULTS
   ========================================================= */

function renderResults(result) {

    const score = safeNumber(
        result.risk_score
    );

    const level =
        result.risk_level ||
        "SAFE";

    const resultClassification =
        result.classification ||
        "SAFE";

    const signals =
        result.signals || {};

    const indicators =
        Array.isArray(result.threat_indicators)
            ? result.threat_indicators
            : [];

    const explanation =
        Array.isArray(result.explanation)
            ? result.explanation
            : [];

    const resultRecommendations =
        Array.isArray(result.recommendations)
            ? result.recommendations
            : [];

    renderRiskScore(score);

    renderRiskLevel(level);

    renderClassification(
        resultClassification
    );

    renderSignals(signals);

    renderThreatIndicators(
        indicators
    );

    renderAssessment(
        explanation
    );

    renderRecommendations(
        resultRecommendations
    );

    resultsPanel.classList.remove(
        "hidden"
    );

    resultsPanel.scrollIntoView({
        behavior: "smooth",
        block: "start",
    });
}


/* =========================================================
   RISK SCORE
   ========================================================= */

function renderRiskScore(score) {

    const clampedScore =
        Math.max(
            0,
            Math.min(
                100,
                Math.round(score)
            )
        );

    animateNumber(
        riskScore,
        0,
        clampedScore,
        750
    );

    animateNumber(
        scoreRingValue,
        0,
        clampedScore,
        750
    );

    updateScoreRing(
        clampedScore
    );
}


/* =========================================================
   SCORE RING
   ========================================================= */

function updateScoreRing(score) {

    const degrees =
        (score / 100) * 360;

    let ringColor =
        "var(--cyan)";

    if (score >= 80) {

        ringColor =
            "var(--red)";

    } else if (score >= 60) {

        ringColor =
            "#ff8a3d";

    } else if (score >= 40) {

        ringColor =
            "var(--yellow)";

    } else if (score < 20) {

        ringColor =
            "var(--green)";
    }

    document
        .querySelector(".score-ring")
        .style.background =
        `conic-gradient(
            ${ringColor} ${degrees}deg,
            rgba(255, 255, 255, 0.07) ${degrees}deg
        )`;
}


/* =========================================================
   RISK LEVEL
   ========================================================= */

function renderRiskLevel(level) {

    riskLevel.textContent =
        String(level).toUpperCase();

    RISK_CLASS_NAMES.forEach(
        (className) => {
            resultsPanel.classList.remove(
                className
            );
        }
    );

    const normalized =
        String(level)
            .trim()
            .toUpperCase();

    if (normalized === "SAFE") {

        resultsPanel.classList.add(
            "risk-safe"
        );

    } else if (normalized === "LOW RISK") {

        resultsPanel.classList.add(
            "risk-low"
        );

    } else if (normalized === "SUSPICIOUS") {

        resultsPanel.classList.add(
            "risk-suspicious"
        );

    } else if (normalized === "HIGH RISK") {

        resultsPanel.classList.add(
            "risk-high"
        );

    } else if (normalized === "CRITICAL") {

        resultsPanel.classList.add(
            "risk-critical"
        );
    }
}


/* =========================================================
   CLASSIFICATION
   ========================================================= */

function renderClassification(
    resultClassification
) {

    classification.textContent =
        String(resultClassification)
            .toUpperCase();
}


/* =========================================================
   SIGNALS
   ========================================================= */

function renderSignals(signals) {

    const content =
        signals.content || {};

    const sender =
        signals.sender || {};

    const urls =
        signals.urls || {};

    const contentValue =
        safeNumber(content.score);

    const contentMaximum =
        safeNumber(
            content.max_score,
            40
        );

    const senderValue =
        safeNumber(sender.score);

    const senderMaximum =
        safeNumber(
            sender.max_score,
            25
        );

    const urlValue =
        safeNumber(urls.score);

    const urlMaximum =
        safeNumber(
            urls.max_score,
            35
        );

    contentScore.textContent =
        `${contentValue} / ${contentMaximum}`;

    senderScore.textContent =
        `${senderValue} / ${senderMaximum}`;

    urlScore.textContent =
        `${urlValue} / ${urlMaximum}`;

    updateSignalBar(
        contentBar,
        contentValue,
        contentMaximum
    );

    updateSignalBar(
        senderBar,
        senderValue,
        senderMaximum
    );

    updateSignalBar(
        urlBar,
        urlValue,
        urlMaximum
    );

    renderContentSummary(
        content
    );

    renderSenderSummary(
        sender
    );

    renderURLSummary(
        urls
    );
}


/* =========================================================
   SIGNAL BAR
   ========================================================= */

function updateSignalBar(
    element,
    value,
    maximum
) {

    if (!maximum || maximum <= 0) {

        element.style.width = "0%";

        return;
    }

    const percentage =
        Math.max(
            0,
            Math.min(
                100,
                (value / maximum) * 100
            )
        );

    element.style.width =
        `${percentage}%`;
}


/* =========================================================
   CONTENT SUMMARY
   ========================================================= */

function renderContentSummary(
    content
) {

    const findings =
        Array.isArray(content.findings)
            ? content.findings
            : [];

    if (findings.length === 0) {

        contentSummary.textContent =
            "No suspicious content indicators detected.";

        return;
    }

    contentSummary.textContent =
        `${findings.length} content indicator${
            findings.length === 1
                ? ""
                : "s"
        } detected.`;
}


/* =========================================================
   SENDER SUMMARY
   ========================================================= */

function renderSenderSummary(
    sender
) {

    const findings =
        Array.isArray(sender.findings)
            ? sender.findings
            : [];

    const domain =
        sender.domain || "";

    if (findings.length === 0) {

        if (domain) {

            senderSummary.textContent =
                `Sender domain analyzed: ${domain}`;

        } else {

            senderSummary.textContent =
                "No sender warning indicators detected.";
        }

        return;
    }

    if (domain) {

        senderSummary.textContent =
            `${findings.length} sender indicator${
                findings.length === 1
                    ? ""
                    : "s"
            } detected for ${domain}.`;

    } else {

        senderSummary.textContent =
            `${findings.length} sender indicator${
                findings.length === 1
                    ? ""
                    : "s"
            } detected.`;
    }
}


/* =========================================================
   URL SUMMARY
   ========================================================= */

function renderURLSummary(
    urls
) {

    const count =
        safeNumber(urls.count);

    if (count === 0) {

        urlSummary.textContent =
            "No URLs detected in the email body.";

        return;
    }

    const items =
        Array.isArray(urls.items)
            ? urls.items
            : [];

    const suspiciousURLCount =
        items.filter(
            (item) =>
                safeNumber(item.score) > 0
        ).length;

    if (suspiciousURLCount > 0) {

        urlSummary.textContent =
            `${count} URL${
                count === 1
                    ? ""
                    : "s"
            } detected, ${suspiciousURLCount} with warning signals.`;

    } else {

        urlSummary.textContent =
            `${count} URL${
                count === 1
                    ? ""
                    : "s"
            } detected.`;
    }
}


/* =========================================================
   THREAT INDICATORS
   ========================================================= */

function renderThreatIndicators(
    indicators
) {

    threatIndicators.innerHTML = "";

    if (indicators.length === 0) {

        threatIndicators.innerHTML = `
            <div class="empty-state">
                NO THREAT INDICATORS DETECTED
            </div>
        `;

        return;
    }

    indicators.forEach(
        (indicator) => {

            const item =
                document.createElement("article");

            item.className =
                "threat-item";

            const icon =
                document.createElement("div");

            icon.className =
                "threat-item-icon";

            icon.textContent = "⚠";

            const content =
                document.createElement("div");

            const title =
                document.createElement("div");

            title.className =
                "threat-item-title";

            title.textContent =
                indicator.indicator ||
                "Unknown indicator";

            const description =
                document.createElement("div");

            description.className =
                "threat-item-description";

            description.textContent =
                indicator.description ||
                "No additional information available.";

            const severity =
                document.createElement("span");

            severity.className =
                "severity-badge";

            severity.textContent =
                indicator.severity ||
                "LOW";

            content.appendChild(title);

            content.appendChild(
                description
            );

            content.appendChild(
                severity
            );

            const score =
                document.createElement("div");

            score.className =
                "threat-item-score";

            const contribution =
                safeNumber(
                    indicator.score_contribution
                );

            score.textContent =
                `+${contribution}`;

            item.appendChild(icon);

            item.appendChild(content);

            item.appendChild(score);

            threatIndicators.appendChild(item);
        }
    );
}


/* =========================================================
   SECURITY ASSESSMENT
   ========================================================= */

function renderAssessment(
    explanation
) {

    securityAssessment.innerHTML = "";

    if (explanation.length === 0) {

        const paragraph =
            document.createElement("p");

        paragraph.textContent =
            "No additional assessment information was returned.";

        securityAssessment.appendChild(
            paragraph
        );

        return;
    }

    explanation.forEach(
        (text) => {

            const paragraph =
                document.createElement("p");

            paragraph.textContent =
                text;

            securityAssessment.appendChild(
                paragraph
            );
        }
    );
}


/* =========================================================
   RECOMMENDATIONS
   ========================================================= */

function renderRecommendations(
    recommendationList
) {

    recommendations.innerHTML = "";

    if (
        recommendationList.length === 0
    ) {

        recommendationList = [
            "Continue to use normal email security practices."
        ];
    }

    recommendationList.forEach(
        (recommendation) => {

            const item =
                document.createElement("div");

            item.className =
                "recommendation-item";

            const icon =
                document.createElement("span");

            icon.className =
                "recommendation-icon";

            icon.textContent = "▸";

            const text =
                document.createElement("span");

            text.textContent =
                recommendation;

            item.appendChild(icon);

            item.appendChild(text);

            recommendations.appendChild(
                item
            );
        }
    );
}


/* =========================================================
   ERROR HANDLING
   ========================================================= */

function showError(message) {

    errorMessage.textContent =
        message ||
        "Unable to analyze the email.";

    errorPanel.classList.remove(
        "hidden"
    );

    errorPanel.scrollIntoView({
        behavior: "smooth",
        block: "nearest",
    });
}


function hideError() {

    errorPanel.classList.add(
        "hidden"
    );
}


/* =========================================================
   RESET APPLICATION
   ========================================================= */

function resetApplication() {

    senderInput.value = "";

    subjectInput.value = "";

    bodyInput.value = "";

    updateCharacterCount();

    hideError();

    resultsPanel.classList.add(
        "hidden"
    );

    scanningPanel.classList.add(
        "hidden"
    );

    scannerProgressBar.style.width =
        "0%";

    riskScore.textContent = "0";

    scoreRingValue.textContent = "0";

    riskLevel.textContent = "SAFE";

    classification.textContent = "SAFE";

    contentScore.textContent =
        "0 / 40";

    senderScore.textContent =
        "0 / 25";

    urlScore.textContent =
        "0 / 35";

    contentBar.style.width = "0%";

    senderBar.style.width = "0%";

    urlBar.style.width = "0%";

    contentSummary.textContent =
        "No content analysis performed.";

    senderSummary.textContent =
        "No sender analysis performed.";

    urlSummary.textContent =
        "No URLs detected.";

    threatIndicators.innerHTML = "";

    securityAssessment.innerHTML = "";

    recommendations.innerHTML = "";

    RISK_CLASS_NAMES.forEach(
        (className) => {
            resultsPanel.classList.remove(
                className
            );
        }
    );

    updateScoreRing(0);

    senderInput.focus();

    window.scrollTo({
        top: 0,
        behavior: "smooth",
    });
}


/* =========================================================
   NUMBER ANIMATION
   ========================================================= */

function animateNumber(
    element,
    start,
    end,
    duration
) {

    const startTime =
        performance.now();

    function update(currentTime) {

        const elapsed =
            currentTime - startTime;

        const progress =
            Math.min(
                elapsed / duration,
                1
            );

        const easedProgress =
            1 - Math.pow(
                1 - progress,
                3
            );

        const currentValue =
            Math.round(
                start +
                (
                    end - start
                ) *
                easedProgress
            );

        element.textContent =
            currentValue;

        if (progress < 1) {

            requestAnimationFrame(
                update
            );
        }
    }

    requestAnimationFrame(update);
}


/* =========================================================
   SAFE NUMBER HELPER
   ========================================================= */

function safeNumber(
    value,
    fallback = 0
) {

    const number =
        Number(value);

    if (
        Number.isFinite(number)
    ) {
        return number;
    }

    return fallback;
}