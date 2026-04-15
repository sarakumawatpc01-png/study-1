function buildBehaviorInsights(metrics) {
  const out = [];
  if (metrics.skipReasons.too_difficult > metrics.skipReasons.already_knew) out.push('User skips difficult tasks');
  if (metrics.earlyCompletionFrequency >= 2) out.push('User finishes early often');
  if (metrics.interruptedSessions >= 1) out.push('Interrupted sessions suggest improving focus blocks');
  if (!out.length) out.push('Behavior stable this period');
  return out;
}

function summarizeEvents(events) {
  const metrics = {
    totalStarts: 0,
    totalCompletions: 0,
    totalSkips: 0,
    interruptedSessions: 0,
    earlyCompletionFrequency: 0,
    timeVsSuggested: [],
    skipReasons: {
      too_difficult: 0,
      already_knew: 0,
      not_enough_time: 0,
      feeling_low: 0,
      other: 0,
    },
  };

  for (const e of events) {
    if (e.event_type === 'started') metrics.totalStarts += 1;
    if (e.event_type === 'completed') {
      metrics.totalCompletions += 1;
      if (Number.isFinite(e.actual_time) && Number.isFinite(e.suggested_time)) {
        metrics.timeVsSuggested.push(e.actual_time - e.suggested_time);
        if (e.actual_time < e.suggested_time) metrics.earlyCompletionFrequency += 1;
      }
    }
    if (e.event_type === 'skipped') {
      metrics.totalSkips += 1;
      const k = e.event_reason || 'other';
      metrics.skipReasons[k] = (metrics.skipReasons[k] || 0) + 1;
    }
    if (e.event_type === 'interrupted') metrics.interruptedSessions += 1;
  }

  const completionRate = metrics.totalStarts ? Math.round((metrics.totalCompletions / metrics.totalStarts) * 100) : 0;
  const avgDelta = metrics.timeVsSuggested.length
    ? Math.round(metrics.timeVsSuggested.reduce((a, b) => a + b, 0) / metrics.timeVsSuggested.length)
    : 0;

  return {
    completionRate,
    skipFrequency: metrics.totalSkips,
    skipReasons: metrics.skipReasons,
    earlyCompletionFrequency: metrics.earlyCompletionFrequency,
    interruptedSessions: metrics.interruptedSessions,
    averageTimeVsSuggestedMinutes: avgDelta,
    insights: buildBehaviorInsights(metrics),
  };
}

function parseDateMs(value) {
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

function buildUsageSessions(apiLogs, gapMinutes = 30) {
  const sorted = [...(apiLogs || [])]
    .map((row) => ({ ...row, _ms: parseDateMs(row.created_at) }))
    .filter((row) => row._ms != null)
    .sort((a, b) => a._ms - b._ms);
  if (!sorted.length) return [];
  const gapMs = gapMinutes * 60 * 1000;
  const sessions = [];
  let current = { start_ms: sorted[0]._ms, end_ms: sorted[0]._ms, requests: 1 };
  for (let i = 1; i < sorted.length; i += 1) {
    const row = sorted[i];
    if (row._ms - current.end_ms > gapMs) {
      sessions.push(current);
      current = { start_ms: row._ms, end_ms: row._ms, requests: 1 };
    } else {
      current.end_ms = row._ms;
      current.requests += 1;
    }
  }
  sessions.push(current);
  return sessions.map((s) => ({
    ...s,
    duration_minutes: Math.max(1, Math.round((s.end_ms - s.start_ms) / 60000)),
    start_at: new Date(s.start_ms).toISOString(),
    end_at: new Date(s.end_ms).toISOString(),
  }));
}

function buildTimeAnalytics(apiLogs) {
  const sessions = buildUsageSessions(apiLogs, 30);
  const totalTimeSpentMinutes = sessions.reduce((sum, s) => sum + Number(s.duration_minutes || 0), 0);
  const activeDays = new Set(sessions.map((s) => String(s.start_at).slice(0, 10))).size;
  return {
    sessions,
    activeDays,
    totalTimeSpentMinutes,
    averageDailyAppUsageMinutes: activeDays ? Number((totalTimeSpentMinutes / activeDays).toFixed(2)) : 0,
  };
}

function buildMoodTimeline(moods) {
  return [...(moods || [])]
    .map((m) => ({ mood: m.mood, note: m.note || null, created_at: m.created_at }))
    .sort((a, b) => (parseDateMs(a.created_at) || 0) - (parseDateMs(b.created_at) || 0));
}

function buildAcademicProgress(mockTests, tasks) {
  const tests = (mockTests || []).map((t) => {
    const score = Number(t.score || 0);
    const total = Math.max(1, Number(t.total || 0));
    return {
      id: t.id,
      name: t.name,
      score,
      total,
      pct: Number(((score / total) * 100).toFixed(2)),
      created_at: t.created_at,
    };
  });
  const taskStats = { pending: 0, completed: 0, skipped: 0, in_progress: 0, other: 0 };
  for (const task of tasks || []) {
    const status = String(task.status || 'other').toLowerCase().replace('-', '_');
    if (status in taskStats) taskStats[status] += 1;
    else taskStats.other += 1;
  }
  return {
    mockTests: tests,
    averageMockPct: tests.length ? Number((tests.reduce((s, t) => s + t.pct, 0) / tests.length).toFixed(2)) : 0,
    tasks: taskStats,
  };
}

function buildGapFinder(errorJournal) {
  const topicMap = new Map();
  for (const row of errorJournal || []) {
    const topic = String(row.topic || 'unknown').trim() || 'unknown';
    if (!topicMap.has(topic)) topicMap.set(topic, { topic, errors: 0, recent_examples: [] });
    const entry = topicMap.get(topic);
    entry.errors += 1;
    if (entry.recent_examples.length < 3) entry.recent_examples.push(row.question);
  }
  const weakSubTopics = [...topicMap.values()].sort((a, b) => b.errors - a.errors).slice(0, 5);
  return {
    weakSubTopics,
    customMockSuggestion: weakSubTopics.length
      ? {
          title: 'Custom Mock Test Recommendation',
          focus_topics: weakSubTopics.slice(0, 3).map((x) => x.topic),
          rationale: 'High recurring error frequency detected in error journal',
        }
      : null,
  };
}

function buildUser360({ user, moods, apiLogs, mockTests, tasks, errorJournal }) {
  return {
    user,
    moodPsychology: {
      timeline: buildMoodTimeline(moods),
    },
    timeAnalytics: buildTimeAnalytics(apiLogs),
    academicProgress: buildAcademicProgress(mockTests, tasks),
    gapFinder: buildGapFinder(errorJournal),
    billingAccess: {
      package_name: user?.package_name || 'free',
      is_active: Number(user?.is_active) === 1,
    },
  };
}

module.exports = {
  summarizeEvents,
  buildUsageSessions,
  buildTimeAnalytics,
  buildMoodTimeline,
  buildAcademicProgress,
  buildGapFinder,
  buildUser360,
};
