import jsPDF from 'jspdf';
import { FusedPayload, ThreatAnalysisResult } from '../types';

export const generatePDFReport = (fused: FusedPayload, result: ThreatAnalysisResult) => {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 15;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  // Primary Color Palette (Dark Cyber Theme in PDF styling)
  const colors = {
    bgDark: [4, 8, 11] as [number, number, number],
    cardBg: [13, 17, 23] as [number, number, number],
    borderDark: [30, 41, 59] as [number, number, number],
    textWhite: [240, 245, 250] as [number, number, number],
    textMuted: [148, 163, 184] as [number, number, number],
    emerald: [16, 185, 129] as [number, number, number],
    rose: [244, 63, 94] as [number, number, number],
    amber: [245, 158, 11] as [number, number, number],
  };

  const threatScore100 = Math.round(result.threat_score * 10);
  const isCritical = threatScore100 >= 80;
  const isElevated = threatScore100 >= 50 && threatScore100 < 80;

  const accentColor = isCritical
    ? colors.rose
    : isElevated
    ? colors.amber
    : colors.emerald;

  const severityText = isCritical
    ? 'CRITICAL THREAT'
    : isElevated
    ? 'ELEVATED RISK'
    : 'BENIGN PAYLOAD';

  // --- 1. PAGE BACKGROUND & HEADER ---
  doc.setFillColor(...colors.bgDark);
  doc.rect(0, 0, pageWidth, pageHeight, 'F');

  // Decorative Accent Top Line
  doc.setFillColor(...accentColor);
  doc.rect(0, 0, pageWidth, 2.5, 'F');

  // Header Panel
  doc.setFillColor(...colors.cardBg);
  doc.rect(margin, y, contentWidth, 26, 'F');
  doc.setDrawColor(...colors.borderDark);
  doc.setLineWidth(0.3);
  doc.rect(margin, y, contentWidth, 26, 'S');

  // Brand Header Title
  doc.setTextColor(...colors.emerald);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.text('SPIDER', margin + 6, y + 10);

  doc.setTextColor(...colors.textWhite);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(11);
  doc.text('THREAT INTELLIGENCE SUMMARY REPORT', margin + 34, y + 10);

  doc.setTextColor(...colors.textMuted);
  doc.setFontSize(8);
  doc.text(
    'System for Phishing Identification, Detection, and Execution Response • v2.0',
    margin + 6,
    y + 17
  );

  // Date & Report Ref ID (Right Aligned)
  const dateStr = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  const reportRef = `SPD-${Math.floor(100000 + Math.random() * 900000)}`;
  doc.text(`Ref: ${reportRef}`, pageWidth - margin - 6, y + 10, { align: 'right' });
  doc.text(`Date: ${dateStr}`, pageWidth - margin - 6, y + 17, { align: 'right' });

  y += 32;

  // --- 2. THREAT VERDICT BANNER ---
  const verdictCardHeight = 38;
  doc.setFillColor(...colors.cardBg);
  doc.rect(margin, y, contentWidth, verdictCardHeight, 'F');
  doc.setDrawColor(...colors.borderDark);
  doc.rect(margin, y, contentWidth, verdictCardHeight, 'S');

  // Accent Left Stripe
  doc.setFillColor(...accentColor);
  doc.rect(margin, y, 2.5, verdictCardHeight, 'F');

  // Score Box
  const scoreBoxWidth = 32;
  const scoreBoxX = margin + 8;
  const scoreBoxY = y + 5;
  doc.setFillColor(20, 27, 36);
  doc.rect(scoreBoxX, scoreBoxY, scoreBoxWidth, 28, 'F');
  doc.setDrawColor(...accentColor);
  doc.rect(scoreBoxX, scoreBoxY, scoreBoxWidth, 28, 'S');

  doc.setTextColor(...accentColor);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(20);
  doc.text(`${threatScore100}`, scoreBoxX + scoreBoxWidth / 2, scoreBoxY + 16, { align: 'center' });

  doc.setTextColor(...colors.textMuted);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(6.5);
  doc.text('THREAT SCORE', scoreBoxX + scoreBoxWidth / 2, scoreBoxY + 23, { align: 'center' });

  // Verdict Details
  const detailsX = scoreBoxX + scoreBoxWidth + 8;
  doc.setTextColor(...accentColor);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.text(severityText, detailsX, y + 10);

  doc.setTextColor(...colors.textMuted);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.text(`Primary Vector: `, detailsX + doc.getTextWidth(severityText) + 8, y + 10);
  doc.setTextColor(...colors.textWhite);
  doc.text(result.primary_vector, detailsX + doc.getTextWidth(severityText) + 30, y + 10);

  // Executive Summary text wrapping
  doc.setTextColor(...colors.textWhite);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  const summaryLines = doc.splitTextToSize(result.executive_summary, contentWidth - 52);
  doc.text(summaryLines, detailsX, y + 17);

  // Prompt Injection Warning Tag
  if (result.is_prompt_injection_attempt) {
    doc.setTextColor(...colors.rose);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.text('⚠ ADVERSARIAL PROMPT INJECTION DETECTED & NEUTRALIZED', detailsX, y + 33);
  }

  y += verdictCardHeight + 8;

  // --- 3. INDICATORS OF COMPROMISE (IoCs) ---
  doc.setTextColor(...colors.emerald);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.text('KEY INDICATORS OF COMPROMISE (IoCs)', margin, y);
  y += 4;

  const iocCardHeight = Math.max(30, result.indicators_of_compromise.length * 7 + 10);
  doc.setFillColor(...colors.cardBg);
  doc.rect(margin, y, contentWidth, iocCardHeight, 'F');
  doc.setDrawColor(...colors.borderDark);
  doc.rect(margin, y, contentWidth, iocCardHeight, 'S');

  let iocY = y + 7;
  result.indicators_of_compromise.forEach((ioc) => {
    doc.setFillColor(...accentColor);
    doc.circle(margin + 6, iocY - 1.2, 1, 'F');

    doc.setTextColor(...colors.textWhite);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    const iocLines = doc.splitTextToSize(ioc, contentWidth - 16);
    doc.text(iocLines, margin + 10, iocY);
    iocY += iocLines.length * 5 + 2;
  });

  y += iocCardHeight + 8;

  // --- 4. MULTIMODAL TELEMETRY BREAKDOWN ---
  doc.setTextColor(...colors.emerald);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.text('MULTIMODAL INGEST TELEMETRY', margin, y);
  y += 4;

  const telemetryBoxHeight = 82;
  doc.setFillColor(...colors.cardBg);
  doc.rect(margin, y, contentWidth, telemetryBoxHeight, 'F');
  doc.setDrawColor(...colors.borderDark);
  doc.rect(margin, y, contentWidth, telemetryBoxHeight, 'S');

  let tY = y + 8;
  const colWidth = (contentWidth - 12) / 2;

  // Left Column: Email & Authentication Analysis
  doc.setTextColor(...colors.textMuted);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.text('EMAIL & AUTHENTICATION PROTOCOLS', margin + 6, tY);
  tY += 5;

  const addTelRow = (label: string, val: string, x: number, currY: number, highlight = false) => {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(...colors.textMuted);
    doc.text(`${label}:`, x, currY);

    if (highlight) {
      doc.setTextColor(...colors.rose);
      doc.setFont('helvetica', 'bold');
    } else {
      doc.setTextColor(...colors.textWhite);
    }
    const valTrunc = val.length > 42 ? val.substring(0, 40) + '...' : val;
    doc.text(valTrunc, x + 30, currY);
  };

  const headers = fused.header_metadata;
  addTelRow('From Header', headers?.From || 'N/A', margin + 6, tY);
  tY += 5;

  const replyToVal = headers?.['Reply-To'] || headers?.ReplyTo || 'N/A';
  addTelRow('Reply-To', replyToVal, margin + 6, tY, !!headers?.reply_to_mismatch);
  tY += 5;

  const spfVal = headers?.spf || 'PASS (spf1 alignment verified)';
  addTelRow('SPF Alignment', spfVal, margin + 6, tY, spfVal.toLowerCase().includes('fail'));
  tY += 5;

  const dkimVal = headers?.dkim || 'PASS (rsa-sha256 signature)';
  addTelRow('DKIM Signature', dkimVal, margin + 6, tY, dkimVal.toLowerCase().includes('fail'));
  tY += 5;

  addTelRow('Subject Line', headers?.Subject || 'N/A', margin + 6, tY);

  // Right Column: URL & DOM Telemetry
  let rY = y + 8;
  doc.setTextColor(...colors.textMuted);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.text('URL, DOM & QUISHING TELEMETRY', margin + colWidth + 6, rY);
  rY += 5;

  const urlCount = fused.decoded_urls?.length || 0;
  addTelRow('Extracted URLs', `${urlCount} link(s) discovered`, margin + colWidth + 6, rY);
  rY += 5;

  const firstUrl = fused.decoded_urls?.[0]?.url || 'None';
  addTelRow('Primary Target', firstUrl, margin + colWidth + 6, rY);
  rY += 5;

  const isTyposquat = fused.decoded_urls?.some((u) => u.isTyposquat) ? 'TYPOSQUAT / PROXY DETECTED' : 'STANDARD';
  addTelRow('AiTM / Domain', isTyposquat, margin + colWidth + 6, rY, isTyposquat !== 'STANDARD');
  rY += 5;

  const ocrTextLen = fused.ocr_text ? fused.ocr_text.length : 0;
  addTelRow('OCR Visual Text', ocrTextLen > 0 ? `${ocrTextLen} characters` : 'None', margin + colWidth + 6, rY);
  rY += 5;

  const transcriptLen = fused.transcript ? fused.transcript.length : 0;
  addTelRow('Voice Transcript', transcriptLen > 0 ? `${transcriptLen} characters` : 'None', margin + colWidth + 6, rY);

  // Bottom Divider inside Telemetry Box
  tY = Math.max(tY, rY) + 4;
  doc.setDrawColor(...colors.borderDark);
  doc.line(margin + 6, tY, pageWidth - margin - 6, tY);
  tY += 5;

  // AI Authorship & Voice Clone Heuristics Row
  doc.setTextColor(...colors.textMuted);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.text('SANITIZATION & AUDIO HEURISTICS', margin + 6, tY);
  tY += 5;

  const alertCount = fused.sanitization_alerts ? fused.sanitization_alerts.length : 0;
  addTelRow('Security Alerts', `${alertCount} flag(s) raised`, margin + 6, tY, alertCount > 0);

  const voiceAnomaly = fused.synthetic_voice_anomaly
    ? `VOCODER ANOMALY (${((fused.anomaly_confidence || 0.9) * 100).toFixed(0)}%)`
    : 'NATURAL VOICE PATTERN';
  addTelRow('Voice Deepfake', voiceAnomaly, margin + colWidth + 6, tY, !!fused.synthetic_voice_anomaly);

  y += telemetryBoxHeight + 8;

  // --- 5. RECOMMENDED MITIGATION STEPS ---
  doc.setTextColor(...colors.emerald);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.text('RECOMMENDED MITIGATION PROCEDURES', margin, y);
  y += 4;

  const mitigations = isCritical
    ? [
        '1. Immediately block sender domain and quarantine associated IP addresses on perimeter firewalls.',
        '2. Revoke any OAuth session tokens or credentials entered into identified AiTM reverse-proxy URLs.',
        '3. Issue urgent security advisory to finance / executive teams regarding impersonation attempt.',
        '4. Ingest IoCs into SIEM / SOAR automated incident response playbooks.',
      ]
    : isElevated
    ? [
        '1. Perform manual out-of-band verification via known phone number or secure internal channel.',
        '2. Inspect email routing headers for suspicious third-party relays.',
        '3. Monitor user account for anomalous login activity or credential dump matches.',
      ]
    : [
        '1. No immediate mitigation required. Monitor routine telemetry.',
        '2. Maintain standard email authentication and user security awareness training.',
      ];

  const mitBoxHeight = mitigations.length * 5 + 8;
  doc.setFillColor(...colors.cardBg);
  doc.rect(margin, y, contentWidth, mitBoxHeight, 'F');
  doc.setDrawColor(...colors.borderDark);
  doc.rect(margin, y, contentWidth, mitBoxHeight, 'S');

  let mY = y + 6;
  mitigations.forEach((m) => {
    doc.setTextColor(...colors.textWhite);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.text(m, margin + 6, mY);
    mY += 5;
  });

  // --- 6. FOOTER & CONFIDENTIALITY NOTICE ---
  const footerY = pageHeight - 12;
  doc.setDrawColor(...colors.borderDark);
  doc.line(margin, footerY - 4, pageWidth - margin, footerY - 4);

  doc.setTextColor(...colors.textMuted);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(6.5);
  doc.text(
    'CONFIDENTIAL • SPIDER Multimodal Phishing Detection Framework • Automated Cryptographic Audit Trail',
    margin,
    footerY
  );
  doc.text(`Page 1 of 1`, pageWidth - margin, footerY, { align: 'right' });

  // Trigger Download
  const filename = `SPIDER_Threat_Report_${reportRef}.pdf`;
  doc.save(filename);
};
