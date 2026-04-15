const pdfParseLib = require('pdf-parse');

function normalizeWhitespace(value) {
  return String(value || '').replace(/\r/g, '').trim();
}

function extractDiagramRefs(text) {
  const refs = [];
  const re = /(diagram|figure|img|image)\s*[:#-]?\s*([A-Za-z0-9._/-]+)/ig;
  let match;
  while ((match = re.exec(text))) {
    refs.push({ type: String(match[1] || '').toLowerCase(), ref: match[2] });
  }
  return refs;
}

function parseAnswerKeys(text) {
  const map = new Map();
  const re = /(?:Question\s*)?(\d+)\s*[:.)-]?\s*([ABCD])\b(?:\s*[-–:]\s*(.+))?/ig;
  let match;
  while ((match = re.exec(text))) {
    map.set(Number(match[1]), {
      option: String(match[2]).toUpperCase(),
      explanation: normalizeWhitespace(match[3] || ''),
    });
  }
  return map;
}

function parseOptions(block) {
  const options = [];
  const re = /^\s*([ABCD])\s*[).:-]\s*(.+)$/gim;
  let match;
  while ((match = re.exec(block))) {
    options.push({ option: String(match[1]).toUpperCase(), text: normalizeWhitespace(match[2]) });
  }
  return options;
}

function extractPageCount(result) {
  if (!result || typeof result !== 'object') return 0;
  if (Number.isFinite(Number(result.total))) return Number(result.total);
  if (Number.isFinite(Number(result.numpages))) return Number(result.numpages);
  if (Array.isArray(result.pages)) return result.pages.length;
  return 0;
}

function parseQuestionsFromText(text) {
  const raw = normalizeWhitespace(text);
  const answerKeys = parseAnswerKeys(raw);
  const marker = /Question\s+(\d+)\s*[:.)-]?/ig;
  const markers = [];
  let match;
  while ((match = marker.exec(raw))) {
    markers.push({ number: Number(match[1]), index: match.index, markerEnd: marker.lastIndex });
  }
  if (!markers.length) {
    return { regexMatched: false, questions: [] };
  }

  const questions = [];
  for (let i = 0; i < markers.length; i += 1) {
    const curr = markers[i];
    const next = markers[i + 1];
    const body = raw.slice(curr.markerEnd, next ? next.index : raw.length).trim();
    const lines = body.split('\n').map((line) => line.trim()).filter(Boolean);
    const options = parseOptions(body);
    const questionText = options.length
      ? lines.filter((line) => !/^\s*[ABCD]\s*[).:-]\s*/i.test(line)).join(' ').trim()
      : lines.join(' ').trim();
    const answer = answerKeys.get(curr.number) || null;
    questions.push({
      question_number: curr.number,
      question_text: questionText,
      options,
      answer_key: answer?.option || null,
      explanation: answer?.explanation || null,
      diagram_refs: extractDiagramRefs(body),
      raw_block: body,
    });
  }

  return { regexMatched: true, questions };
}

async function extractTextFromPdfBuffer(fileBuffer) {
  if (typeof pdfParseLib === 'function') {
    const result = await pdfParseLib(fileBuffer);
    return {
      text: normalizeWhitespace(result.text || ''),
      metadata: result.info || result.meta || {},
      num_pages: extractPageCount(result),
    };
  }
  const PDFParse = pdfParseLib?.PDFParse;
  if (!PDFParse) throw new Error('pdf-parse parser not available');
  const parser = new PDFParse({ data: fileBuffer });
  const result = await parser.getText();
  if (typeof parser.destroy === 'function') await parser.destroy().catch(() => {});
  return {
    text: normalizeWhitespace(result.text || ''),
    metadata: result.info || result.meta || {},
    num_pages: extractPageCount(result),
  };
}

function buildFallbackStructuredPayload(rawText) {
  return {
    fallback_mode: 'ai_secondary_requested',
    reason: 'Regex pattern for "Question [0-9]" did not match.',
    note: 'AI call intentionally deferred to minimize cost unless explicitly enabled upstream.',
    raw_text: rawText,
    structured_questions: [],
  };
}

function buildStructuredPayload({ questions, extractedText, extractionMeta, usedAiFallback, sourceFileName, sourceMimeType, metadata }) {
  return {
    source_file_name: sourceFileName,
    source_mime_type: sourceMimeType || 'application/pdf',
    extracted_text: extractedText,
    extraction_meta: extractionMeta,
    used_ai_fallback: usedAiFallback,
    structured_questions: questions,
    metadata: metadata || {},
  };
}

async function processPdfIngestion({ fileBuffer, sourceFileName, sourceMimeType, metadata }) {
  const extraction = await extractTextFromPdfBuffer(fileBuffer);
  const parsed = parseQuestionsFromText(extraction.text);
  const usedAiFallback = !parsed.regexMatched;
  const payload = usedAiFallback
    ? buildFallbackStructuredPayload(extraction.text)
    : buildStructuredPayload({
      questions: parsed.questions,
      extractedText: extraction.text,
      extractionMeta: { num_pages: extraction.num_pages, pdf_info: extraction.metadata },
      usedAiFallback,
      sourceFileName,
      sourceMimeType,
      metadata,
    });

  return {
    usedAiFallback,
    questionCount: parsed.questions.length,
    extractedText: extraction.text,
    data_json: payload,
  };
}

module.exports = {
  parseQuestionsFromText,
  parseAnswerKeys,
  extractTextFromPdfBuffer,
  processPdfIngestion,
};
