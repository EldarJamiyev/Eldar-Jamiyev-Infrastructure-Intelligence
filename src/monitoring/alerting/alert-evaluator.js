/**
 * EJI Alert Evaluator & Incident Dispatcher
 * Evaluates real-time infrastructure telemetry against configured threshold rules.
 */

const MonitoringRepository = require('../../database/repositories/monitoring-repository');

class AlertEvaluator {
  /**
   * Evaluate a condition operator against observed value and threshold
   */
  static checkCondition(operator, observedValue, thresholdValue) {
    const obs = Number(observedValue);
    const thresh = Number(thresholdValue);

    switch (operator) {
      case '>':
        return obs > thresh;
      case '<':
        return obs < thresh;
      case '>=':
        return obs >= thresh;
      case '<=':
        return obs <= thresh;
      case '==':
        return obs === thresh;
      case '!=':
        return obs !== thresh;
      default:
        return false;
    }
  }

  /**
   * Evaluate a single telemetry sample against all active matching alert rules
   */
  static evaluateSample({ ciId, metricName, value, targetCiType = null }) {
    const rules = MonitoringRepository.listAlertRules({ enabledOnly: true });
    const matchingRules = rules.filter(r => {
      if (r.metric_name !== metricName) return false;
      if (r.target_ci_type && targetCiType && r.target_ci_type !== targetCiType) return false;
      return true;
    });

    const results = [];

    for (const rule of matchingRules) {
      const isBreaching = this.checkCondition(rule.condition_operator, value, rule.threshold_value);

      if (isBreaching) {
        // Record or update firing alert
        const alert = MonitoringRepository.recordAlert({
          ruleId: rule.id,
          ciId,
          metricName,
          observedValue: value,
          thresholdValue: rule.threshold_value,
          severity: rule.severity
        });

        // Record notification dispatch
        const notification = MonitoringRepository.recordNotification({
          alertId: alert.id,
          channel: 'syslog',
          destination: 'localhost:514',
          payloadJson: {
            alertId: alert.id,
            rule: rule.name,
            ciId,
            metric: metricName,
            value,
            severity: rule.severity
          }
        });

        results.push({
          ruleId: rule.id,
          ciId,
          status: 'firing',
          alert,
          notification
        });
      }
    }

    return results;
  }

  /**
   * Evaluate a batch of telemetry samples
   */
  static evaluateBatch(samples = []) {
    const allResults = [];
    for (const sample of samples) {
      const res = this.evaluateSample(sample);
      allResults.push(...res);
    }
    return allResults;
  }
}

module.exports = AlertEvaluator;
