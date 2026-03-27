function buildBehaviorInsights(metrics) {
  const out = [];
  if (metrics.skipReasons.too_difficult > metrics.skipReasons.already_knew) {
    out.push('User skips difficult tasks');
  }
  if (metrics.earlyCompletionFrequency >= 2) {
    out.push('User finishes early often');
  }
  if (metrics.interruptedSessions >= 1) {
    out.push('Interrupted sessions suggest improving focus blocks');
  }
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
      if (
        Number.isFinite(e.actual_time) &&
        Number.isFinite(e.suggested_time)
      ) {
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

  const completionRate = metrics.totalStarts
    ? Math.round((metrics.totalCompletions / metrics.totalStarts) * 100)
    : 0;
  const avgDelta = metrics.timeVsSuggested.length
    ? Math.round(
        metrics.timeVsSuggested.reduce((a, b) => a + b, 0) /
          metrics.timeVsSuggested.length
      )
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

module.exports = { summarizeEvents };
