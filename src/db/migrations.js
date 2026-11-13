/**
 * EJII Transactional SQLite Schema Migration Engine
 * Maintains a cryptographic checksum-verified schema_migrations ledger
 * and ensures all NOC topology, security, AI Brain, and Office Equipment
 * tables and indexes exist under WAL mode.
 */

const crypto = require('crypto');

const MIGRATIONS = [
  {
    version: 1,
    name: '001_core_noc_topology_auth_and_audit',
    sql: `
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL,
        full_name TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS topology_nodes (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        layer INTEGER NOT NULL,
        hostname_or_ip TEXT NOT NULL,
        mac_address TEXT,
        vendor TEXT,
        status TEXT DEFAULT 'unknown',
        latency_ms REAL,
        packet_loss REAL DEFAULT 0,
        last_checked TEXT
      );
      CREATE TABLE IF NOT EXISTS topology_edges (
        id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL,
        target_id TEXT NOT NULL,
        protocol TEXT DEFAULT 'TCP/IP',
        port INTEGER DEFAULT 443,
        bandwidth_mbps INTEGER DEFAULT 1000,
        status TEXT DEFAULT 'healthy',
        latency_ms REAL DEFAULT 1.0,
        utilization_pct REAL DEFAULT 5.0
      );
      CREATE TABLE IF NOT EXISTS consumed_action_tokens (
        token_hash TEXT PRIMARY KEY,
        action_type TEXT NOT NULL,
        user_id TEXT NOT NULL,
        consumed_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );
    `
  },
  {
    version: 2,
    name: '002_ai_brain_wal_persistence_tables',
    sql: `
      CREATE TABLE IF NOT EXISTS brain_baselines (
        target TEXT PRIMARY KEY,
        subnet_gateway TEXT,
        min_rtt REAL NOT NULL,
        max_rtt REAL NOT NULL,
        avg_rtt REAL NOT NULL,
        variance REAL DEFAULT 0,
        stddev REAL DEFAULT 0,
        m2 REAL DEFAULT 0,
        sample_count INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'PROVISIONAL_INSUFFICIENT_SAMPLES',
        first_observed TEXT NOT NULL,
        last_observed TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS brain_incidents (
        incident_key TEXT PRIMARY KEY,
        incident_type TEXT NOT NULL,
        target TEXT NOT NULL,
        dest_port INTEGER DEFAULT 0,
        top_hypothesis_id TEXT,
        top_hypothesis_label TEXT,
        confidence INTEGER DEFAULT 0,
        diagnostic_state TEXT DEFAULT 'EVALUATED',
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS brain_calibration (
        incident_type TEXT NOT NULL,
        hypothesis_id TEXT NOT NULL,
        multiplier REAL NOT NULL DEFAULT 1.0,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (incident_type, hypothesis_id)
      );
      CREATE TABLE IF NOT EXISTS brain_feedback_ledger (
        feedback_id TEXT PRIMARY KEY,
        incident_key TEXT NOT NULL,
        incident_type TEXT NOT NULL,
        hypothesis_id TEXT NOT NULL,
        verdict TEXT NOT NULL,
        previous_multiplier REAL NOT NULL,
        updated_multiplier REAL NOT NULL,
        operator_notes TEXT,
        user_id TEXT NOT NULL,
        recorded_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS unified_investigations (
        investigation_id TEXT PRIMARY KEY,
        symptom TEXT NOT NULL,
        process_query TEXT,
        target_host TEXT NOT NULL,
        target_port INTEGER NOT NULL,
        overall_verdict TEXT NOT NULL,
        confidence INTEGER NOT NULL,
        uncertainty_warning INTEGER DEFAULT 0,
        report_json TEXT NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT NOT NULL
      );
    `
  },
  {
    version: 3,
    name: '003_office_equipment_inventory_and_dhcp_events',
    sql: `
      CREATE TABLE IF NOT EXISTS office_equipment_inventory (
        device_id TEXT PRIMARY KEY,
        mac_address TEXT,
        current_ip TEXT NOT NULL,
        last_known_good_ip TEXT,
        device_name TEXT,
        equipment_type TEXT NOT NULL,
        equipment_category TEXT NOT NULL,
        equipment_brand TEXT,
        icon TEXT DEFAULT '💻',
        is_apipa_fault INTEGER DEFAULT 0,
        status TEXT DEFAULT 'ONLINE',
        open_ports_json TEXT DEFAULT '[]',
        passive_os_fingerprint TEXT,
        discovery_source TEXT DEFAULT 'SCANNER',
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_office_equip_ip ON office_equipment_inventory(current_ip);
      CREATE INDEX IF NOT EXISTS idx_office_equip_mac ON office_equipment_inventory(mac_address);
      CREATE INDEX IF NOT EXISTS idx_office_equip_cat ON office_equipment_inventory(equipment_category);

      CREATE TABLE IF NOT EXISTS dhcp_and_ip_events (
        event_id TEXT PRIMARY KEY,
        mac_address TEXT,
        ip_address TEXT NOT NULL,
        previous_ip TEXT,
        event_type TEXT NOT NULL,
        dhcp_message_type TEXT,
        hostname TEXT,
        details TEXT,
        observed_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_dhcp_events_mac ON dhcp_and_ip_events(mac_address);
      CREATE INDEX IF NOT EXISTS idx_dhcp_events_time ON dhcp_and_ip_events(observed_at);
    `
  },
  {
    version: 4,
    name: '004_endpoint_behavioral_profiles_and_autonomous_workflows',
    sql: `
      CREATE TABLE IF NOT EXISTS endpoint_behavioral_profiles (
        target_key TEXT PRIMARY KEY,
        mac_address TEXT,
        icmp_filtered_normal INTEGER DEFAULT 0,
        known_open_ports_json TEXT DEFAULT '[]',
        expected_equipment_type TEXT DEFAULT 'UNKNOWN',
        apipa_flap_count INTEGER DEFAULT 0,
        last_root_cause_id TEXT,
        operator_notes TEXT,
        calibration_json TEXT DEFAULT '{}',
        first_learned_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_endpoint_profile_mac ON endpoint_behavioral_profiles(mac_address);

      CREATE TABLE IF NOT EXISTS autonomous_workflow_runs (
        workflow_id TEXT PRIMARY KEY,
        goal TEXT NOT NULL,
        target_host TEXT NOT NULL,
        target_port INTEGER DEFAULT 0,
        status TEXT NOT NULL,
        top_hypothesis_id TEXT,
        confidence INTEGER DEFAULT 0,
        plain_summary_json TEXT NOT NULL,
        workflow_report_json TEXT NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT NOT NULL
      );
    `
  },
  {
    version: 5,
    name: '005_investigation_sessions_ledger_and_cbr_signatures',
    sql: `
      CREATE TABLE IF NOT EXISTS investigation_sessions (
        session_id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        state TEXT NOT NULL,
        symptom_type TEXT NOT NULL,
        target_host TEXT,
        target_port INTEGER,
        process_name TEXT,
        target_pid INTEGER,
        operator_role TEXT,
        top_hypothesis_id TEXT,
        calibrated_confidence REAL,
        evidence_coverage_ratio REAL,
        orchestration_mode TEXT,
        critic_passed INTEGER DEFAULT 1,
        verification_outcome TEXT,
        plan_json TEXT NOT NULL,
        critic_json TEXT,
        summary_json TEXT
      );

      CREATE TABLE IF NOT EXISTS investigation_evidence_ledger (
        evidence_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        metric_key TEXT NOT NULL,
        evidence_class TEXT NOT NULL,
        outcome TEXT NOT NULL,
        value_json TEXT,
        unit TEXT,
        collector_id TEXT NOT NULL,
        collection_method TEXT NOT NULL,
        is_authoritative INTEGER NOT NULL,
        is_provisional INTEGER NOT NULL,
        timestamp_iso TEXT NOT NULL,
        supports_json TEXT,
        contradicts_json TEXT,
        FOREIGN KEY (session_id) REFERENCES investigation_sessions(session_id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS historical_incident_signatures (
        incident_id TEXT PRIMARY KEY,
        session_id TEXT,
        created_at TEXT NOT NULL,
        symptom_type TEXT NOT NULL,
        signature_vector_json TEXT NOT NULL,
        observed_keys_json TEXT NOT NULL,
        validated_root_cause_id TEXT,
        remediation_recipe_id TEXT,
        remediation_verified INTEGER DEFAULT 0,
        pre_post_delta_json TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_investigation_sessions_created ON investigation_sessions(created_at);
      CREATE INDEX IF NOT EXISTS idx_investigation_evidence_session ON investigation_evidence_ledger(session_id);
      CREATE INDEX IF NOT EXISTS idx_historical_signatures_symptom ON historical_incident_signatures(symptom_type);
    `
  },
  {
    version: 6,
    name: '006_episodic_causal_memory_and_operator_approvals',
    sql: `
      CREATE TABLE IF NOT EXISTS ejii_episodic_causal_memory (
        episode_id TEXT PRIMARY KEY,
        recorded_at TEXT NOT NULL,
        target TEXT NOT NULL,
        provenance TEXT NOT NULL,
        is_simulated INTEGER NOT NULL DEFAULT 0,
        root_cause_domain TEXT NOT NULL,
        executed_runbook_id TEXT,
        resolved INTEGER NOT NULL DEFAULT 0,
        payload_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_episodic_memory_recorded ON ejii_episodic_causal_memory(recorded_at);
      CREATE INDEX IF NOT EXISTS idx_episodic_memory_target ON ejii_episodic_causal_memory(target);

      CREATE TABLE IF NOT EXISTS operator_script_approvals (
        approval_token TEXT PRIMARY KEY,
        operator_id TEXT NOT NULL,
        operator_role TEXT NOT NULL,
        script_name TEXT NOT NULL,
        script_content_sha256 TEXT NOT NULL,
        params_text TEXT NOT NULL DEFAULT '',
        target_scope TEXT NOT NULL DEFAULT '',
        issued_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        consumed_at_ms INTEGER
      );
      CREATE INDEX IF NOT EXISTS idx_script_approvals_exp ON operator_script_approvals(expires_at_ms);
    `
  },
  {
    version: 7,
    name: '007_war_room_sessions_and_atomic_approvals',
    sql: `
      CREATE TABLE IF NOT EXISTS war_room_sessions (
        session_id TEXT PRIMARY KEY,
        parent_session_id TEXT,
        executed_at TEXT NOT NULL,
        status TEXT NOT NULL,
        lifecycle_stage TEXT NOT NULL DEFAULT 'HYPOTHESIS_FORMATION',
        persistence_state TEXT NOT NULL DEFAULT 'DURABLE_SQLITE_WAL',
        payload_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_war_room_sessions_exec ON war_room_sessions(executed_at);
      CREATE INDEX IF NOT EXISTS idx_war_room_sessions_parent ON war_room_sessions(parent_session_id);

      CREATE TABLE IF NOT EXISTS operator_approval_ledger (
        approval_id TEXT PRIMARY KEY,
        approval_token TEXT UNIQUE NOT NULL,
        operator_id TEXT NOT NULL,
        operator_role TEXT NOT NULL,
        auth_source TEXT NOT NULL DEFAULT 'OPERATOR_SESSION',
        script_name TEXT NOT NULL,
        script_sha256 TEXT NOT NULL,
        params_json TEXT NOT NULL DEFAULT '',
        target TEXT NOT NULL DEFAULT 'local_host',
        issued_at TEXT NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        consumed_at TEXT,
        revoked_at TEXT,
        revoked_reason TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_operator_approval_ledger_exp ON operator_approval_ledger(expires_at_ms);
    `
  },
  {
    version: 8,
    name: '008_autonomous_intelligence_and_project_atlas',
    sql: `
      CREATE TABLE IF NOT EXISTS war_room_collector_receipts (
        receipt_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        probe_id TEXT NOT NULL,
        probe_type TEXT NOT NULL,
        target TEXT NOT NULL,
        collector_id TEXT NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT NOT NULL,
        duration_ms REAL NOT NULL,
        timing_target TEXT NOT NULL,
        native_result_code TEXT NOT NULL,
        raw_output_sha256 TEXT NOT NULL,
        hmac_signature TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_wr_collector_receipts_session ON war_room_collector_receipts(session_id, probe_id);

      CREATE TABLE IF NOT EXISTS war_room_dual_approvals (
        approval_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        remediation_action TEXT NOT NULL,
        target TEXT NOT NULL,
        operator_id TEXT NOT NULL,
        operator_username TEXT NOT NULL,
        operator_role TEXT NOT NULL,
        approval_slot TEXT NOT NULL,
        token_signature TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        consumed_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_wr_dual_approvals_session ON war_room_dual_approvals(session_id);

      CREATE TABLE IF NOT EXISTS war_room_remediation_ledger (
        execution_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        remediation_action TEXT NOT NULL,
        target TEXT NOT NULL,
        executor_source TEXT NOT NULL,
        operator_id TEXT NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT NOT NULL,
        exit_code INTEGER NOT NULL DEFAULT 0,
        success INTEGER NOT NULL DEFAULT 1,
        output_summary TEXT NOT NULL,
        hmac_signature TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_wr_remediation_session ON war_room_remediation_ledger(session_id);

      CREATE TABLE IF NOT EXISTS atlas_configs (
        config_id TEXT PRIMARY KEY,
        version INTEGER NOT NULL,
        profile_name TEXT NOT NULL,
        format TEXT NOT NULL DEFAULT 'JSON',
        config_json TEXT NOT NULL,
        checksum_sha256 TEXT NOT NULL,
        validation_status TEXT NOT NULL DEFAULT 'VALID',
        active INTEGER NOT NULL DEFAULT 0,
        created_by TEXT NOT NULL DEFAULT 'system',
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_atlas_configs_version ON atlas_configs(profile_name, version DESC);

      CREATE TABLE IF NOT EXISTS atlas_relays (
        relay_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        bind_addr TEXT NOT NULL,
        bind_port INTEGER NOT NULL,
        transport_protocol TEXT NOT NULL DEFAULT 'TCP_MUX',
        tls_mode TEXT NOT NULL DEFAULT 'TLS_1_3_STRICT',
        auth_mode TEXT NOT NULL DEFAULT 'HMAC_TOKEN_AND_JWT',
        status TEXT NOT NULL DEFAULT 'ONLINE',
        active_clients INTEGER NOT NULL DEFAULT 0,
        active_tunnels INTEGER NOT NULL DEFAULT 0,
        bytes_in INTEGER NOT NULL DEFAULT 0,
        bytes_out INTEGER NOT NULL DEFAULT 0,
        measured_rtt_ms REAL,
        metadata_json TEXT,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS atlas_clients (
        client_id TEXT PRIMARY KEY,
        client_name TEXT NOT NULL,
        relay_id TEXT NOT NULL,
        hostname TEXT NOT NULL,
        os_platform TEXT NOT NULL,
        arch TEXT NOT NULL,
        version TEXT NOT NULL,
        auth_identity TEXT NOT NULL,
        tls_verified INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'CONNECTED',
        last_heartbeat_at TEXT NOT NULL,
        session_expires_at INTEGER NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0,
        metadata_json TEXT,
        registered_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_atlas_clients_relay ON atlas_clients(relay_id, status);

      CREATE TABLE IF NOT EXISTS atlas_proxies (
        proxy_id TEXT PRIMARY KEY,
        proxy_name TEXT NOT NULL UNIQUE,
        client_id TEXT NOT NULL,
        relay_id TEXT NOT NULL,
        proxy_type TEXT NOT NULL,
        bind_addr TEXT NOT NULL DEFAULT '127.0.0.1',
        remote_port INTEGER NOT NULL DEFAULT 0,
        local_ip TEXT NOT NULL,
        local_port INTEGER NOT NULL,
        custom_domains TEXT,
        subdomain TEXT,
        locations_json TEXT,
        load_balance_group TEXT,
        load_balance_strategy TEXT DEFAULT 'ROUND_ROBIN',
        health_check_json TEXT,
        health_status TEXT NOT NULL DEFAULT 'HEALTHY',
        bandwidth_limit_kbps INTEGER DEFAULT 0,
        rate_limit_rps INTEGER DEFAULT 0,
        proxy_protocol_version TEXT DEFAULT 'NONE',
        host_header_rewrite TEXT,
        headers_json TEXT,
        exposure_policy TEXT NOT NULL DEFAULT 'PRIVATE_LOOPBACK',
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        active_connections INTEGER NOT NULL DEFAULT 0,
        total_connections INTEGER NOT NULL DEFAULT 0,
        bytes_in INTEGER NOT NULL DEFAULT 0,
        bytes_out INTEGER NOT NULL DEFAULT 0,
        last_latency_ms REAL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_atlas_proxies_type ON atlas_proxies(proxy_type, status);

      CREATE TABLE IF NOT EXISTS atlas_virtual_networks (
        vnet_id TEXT PRIMARY KEY,
        vnet_name TEXT NOT NULL UNIQUE,
        cidr_block TEXT NOT NULL,
        controller_mode TEXT NOT NULL DEFAULT 'ZERO_TRUST_MESH',
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        peers_json TEXT NOT NULL,
        routes_json TEXT NOT NULL,
        acl_rules_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS atlas_events (
        event_id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'INFO',
        subject_id TEXT NOT NULL,
        summary TEXT NOT NULL,
        details_json TEXT,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_atlas_events_time ON atlas_events(created_at DESC);
    `
  },
  {
    version: 9,
    name: '009_atlas_iii_crypto_keyring_and_distributed_state',
    sql: `
      CREATE TABLE IF NOT EXISTS crypto_key_versions (
        purpose TEXT NOT NULL,
        key_id TEXT NOT NULL,
        secret_fingerprint_sha256 TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        created_at_ms INTEGER NOT NULL,
        rotated_at_ms INTEGER,
        expires_at_ms INTEGER,
        revoked_at_ms INTEGER,
        revocation_reason TEXT,
        PRIMARY KEY (purpose, key_id)
      );
      CREATE INDEX IF NOT EXISTS idx_crypto_key_versions_status ON crypto_key_versions(purpose, status);

      CREATE TABLE IF NOT EXISTS atlas_consumed_nonces (
        nonce TEXT PRIMARY KEY,
        token_digest TEXT,
        client_name TEXT NOT NULL,
        client_id TEXT NOT NULL,
        consumed_at TEXT NOT NULL,
        expires_at_ms INTEGER
      );

      CREATE TABLE IF NOT EXISTS atlas_revoked_tokens (
        token_digest TEXT PRIMARY KEY,
        reason TEXT NOT NULL,
        revoked_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS atlas_jit_grants (
        jit_grant_id TEXT PRIMARY KEY,
        local_ip TEXT NOT NULL,
        local_port INTEGER NOT NULL,
        operator_id TEXT NOT NULL,
        secondary_approver_id TEXT,
        dual_control_verified INTEGER NOT NULL DEFAULT 0,
        reason TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0,
        signature TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_atlas_jit_grants_exp ON atlas_jit_grants(expires_at, revoked);

      CREATE TABLE IF NOT EXISTS war_room_consumed_receipts (
        receipt_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        probe_id TEXT NOT NULL,
        target TEXT NOT NULL,
        consumed_at_ms INTEGER NOT NULL
      );
    `
  },
  {
    version: 10,
    name: '010_atlas_iv_distributed_control_plane_and_closed_loop',
    sql: `
      CREATE TABLE IF NOT EXISTS atlas_sites (
        site_id TEXT PRIMARY KEY,
        site_name TEXT NOT NULL UNIQUE,
        region TEXT NOT NULL DEFAULT 'global-edge',
        cidr_blocks_json TEXT NOT NULL DEFAULT '[]',
        primary_relay_id TEXT NOT NULL,
        backup_relay_id TEXT,
        status TEXT NOT NULL DEFAULT 'CONFIGURED',
        generation INTEGER NOT NULL DEFAULT 1,
        metadata_json TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_atlas_sites_relay ON atlas_sites(primary_relay_id, status);

      CREATE TABLE IF NOT EXISTS atlas_reconciliation_ledger (
        reconcile_id TEXT PRIMARY KEY,
        generation INTEGER NOT NULL,
        drift_detected_count INTEGER NOT NULL DEFAULT 0,
        reconciled_count INTEGER NOT NULL DEFAULT 0,
        details_json TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_atlas_reconcile_gen ON atlas_reconciliation_ledger(generation DESC);

      CREATE TABLE IF NOT EXISTS atlas_closed_loop_incidents (
        incident_id TEXT PRIMARY KEY,
        trigger_type TEXT NOT NULL DEFAULT 'RELAY_LINK_PACKET_LOSS_SPIKE',
        trigger_event TEXT NOT NULL DEFAULT 'RELAY_LINK_PACKET_LOSS_SPIKE',
        subject_id TEXT NOT NULL,
        affected_relay_id TEXT,
        affected_services_json TEXT NOT NULL DEFAULT '[]',
        root_cause_verdict TEXT NOT NULL DEFAULT 'INVESTIGATING',
        remediation_action TEXT NOT NULL DEFAULT 'NONE',
        evidence_bundle_json TEXT NOT NULL DEFAULT '{}',
        blast_radius_json TEXT NOT NULL DEFAULT '{}',
        war_room_causal_json TEXT NOT NULL DEFAULT '{}',
        remediation_action_json TEXT NOT NULL DEFAULT '{}',
        verification_result_json TEXT NOT NULL DEFAULT '{}',
        status TEXT NOT NULL DEFAULT 'OPEN_INVESTIGATING',
        pre_telemetry_json TEXT,
        post_telemetry_json TEXT,
        post_action_verified INTEGER NOT NULL DEFAULT 0,
        war_room_session_id TEXT,
        created_at TEXT NOT NULL,
        resolved_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_atlas_closed_loop_time ON atlas_closed_loop_incidents(created_at DESC);

      CREATE TABLE IF NOT EXISTS atlas_control_plane_approvals (
        approval_id TEXT PRIMARY KEY,
        approver_id TEXT NOT NULL,
        approver_role TEXT NOT NULL,
        target_id TEXT NOT NULL,
        action_type TEXT NOT NULL,
        control_plane_generation INTEGER NOT NULL DEFAULT 1,
        key_id TEXT,
        reason TEXT,
        issued_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        consumed INTEGER NOT NULL DEFAULT 0,
        consumed_by_operator_id TEXT,
        consumed_at TEXT,
        revoked INTEGER NOT NULL DEFAULT 0,
        revoked_at TEXT,
        revocation_reason TEXT,
        signature_hmac_sha256 TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_atlas_cp_approvals_target ON atlas_control_plane_approvals(target_id, action_type, consumed);

      CREATE TABLE IF NOT EXISTS atlas_control_plane_state (
        state_key TEXT PRIMARY KEY,
        state_value TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
    `
  },
  {
    version: 11,
    name: '011_telemetry_critical_evidence_spill_ledger',
    sql: `
      CREATE TABLE IF NOT EXISTS telemetry_critical_evidence_spill_ledger (
        spill_reference_id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        spilled_signatures_count INTEGER NOT NULL DEFAULT 0,
        spilled_occurrences_count INTEGER NOT NULL DEFAULT 0,
        total_event_ids_count INTEGER NOT NULL DEFAULT 0,
        event_ids_json TEXT NOT NULL DEFAULT '[]',
        records_json TEXT NOT NULL DEFAULT '[]',
        metadata_json TEXT NOT NULL DEFAULT '{}'
      );
      CREATE INDEX IF NOT EXISTS idx_telemetry_spill_expires ON telemetry_critical_evidence_spill_ledger(expires_at_ms DESC);
    `
  }
];

function runMigrations(dbInstance, options = {}) {
  if (!dbInstance) {
    try {
      dbInstance = require('./database').db;
    } catch (_) {}
  }
  if (!dbInstance) {
    return { status: 'NO_DB_INSTANCE', appliedCount: 0, totalMigrations: MIGRATIONS.length, migrations: [], error: 'No database instance available' };
  }

  const customMigrations = Array.isArray(options.migrations) ? options.migrations : MIGRATIONS;

  dbInstance.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      checksum TEXT NOT NULL,
      applied_at TEXT NOT NULL
    );
  `);

  try {
    const tableInfo = dbInstance.prepare("PRAGMA table_info('schema_migrations')").all();
    const hasChecksum = tableInfo.some((col) => col.name === 'checksum');
    if (!hasChecksum) {
      dbInstance.exec('ALTER TABLE schema_migrations ADD COLUMN checksum TEXT');
    }
  } catch (alterErr) {
    if (options.strict) throw alterErr;
  }

  const appliedRows = dbInstance.prepare('SELECT version, name, checksum FROM schema_migrations ORDER BY version ASC').all();
  const appliedMap = new Map(appliedRows.map((r) => [Number(r.version), r]));
  const insertMigration = dbInstance.prepare(`
    INSERT OR REPLACE INTO schema_migrations (version, name, checksum, applied_at)
    VALUES (@version, @name, @checksum, @applied_at)
  `);

  let appliedCount = 0;
  let failedVersion = null;
  const ensureLegacyWarRoomColumns = () => {
    try {
      const wrCols = dbInstance.prepare("PRAGMA table_info('war_room_sessions')").all();
      if (Array.isArray(wrCols) && wrCols.length > 0) {
        const colNames = new Set(wrCols.map((c) => c.name));
        if (!colNames.has('parent_session_id')) {
          dbInstance.exec('ALTER TABLE war_room_sessions ADD COLUMN parent_session_id TEXT');
        }
        if (!colNames.has('status')) {
          dbInstance.exec("ALTER TABLE war_room_sessions ADD COLUMN status TEXT NOT NULL DEFAULT 'STABILIZED_MONITORING'");
        }
        if (!colNames.has('lifecycle_stage')) {
          dbInstance.exec("ALTER TABLE war_room_sessions ADD COLUMN lifecycle_stage TEXT NOT NULL DEFAULT 'HYPOTHESIS_FORMATION'");
        }
        if (!colNames.has('persistence_state')) {
          dbInstance.exec("ALTER TABLE war_room_sessions ADD COLUMN persistence_state TEXT NOT NULL DEFAULT 'DURABLE_SQLITE_WAL'");
        }
      }
    } catch (_) {}
  };

  const ensureAtlasClosedLoopIncidentColumns = () => {
    try {
      const incCols = dbInstance.prepare("PRAGMA table_info('atlas_closed_loop_incidents')").all();
      if (Array.isArray(incCols) && incCols.length > 0) {
        const colNames = new Set(incCols.map((c) => c.name));
        const requiredAdditions = [
          ['trigger_type', "TEXT NOT NULL DEFAULT 'RELAY_LINK_PACKET_LOSS_SPIKE'"],
          ['trigger_event', "TEXT NOT NULL DEFAULT 'RELAY_LINK_PACKET_LOSS_SPIKE'"],
          ['affected_relay_id', 'TEXT'],
          ['affected_services_json', "TEXT NOT NULL DEFAULT '[]'"],
          ['root_cause_verdict', "TEXT NOT NULL DEFAULT 'INVESTIGATING'"],
          ['remediation_action', "TEXT NOT NULL DEFAULT 'NONE'"],
          ['evidence_bundle_json', "TEXT NOT NULL DEFAULT '{}'"],
          ['blast_radius_json', "TEXT NOT NULL DEFAULT '{}'"],
          ['war_room_causal_json', "TEXT NOT NULL DEFAULT '{}'"],
          ['remediation_action_json', "TEXT NOT NULL DEFAULT '{}'"],
          ['verification_result_json', "TEXT NOT NULL DEFAULT '{}'"],
          ['pre_telemetry_json', 'TEXT'],
          ['post_telemetry_json', 'TEXT'],
          ['post_action_verified', 'INTEGER NOT NULL DEFAULT 0'],
          ['war_room_session_id', 'TEXT']
        ];
        for (const [col, def] of requiredAdditions) {
          if (!colNames.has(col)) {
            dbInstance.exec(`ALTER TABLE atlas_closed_loop_incidents ADD COLUMN ${col} ${def}`);
          }
        }
      }
    } catch (_) {}

    try {
      dbInstance.exec(`
        CREATE TABLE IF NOT EXISTS atlas_control_plane_approvals (
          approval_id TEXT PRIMARY KEY,
          approver_id TEXT NOT NULL,
          approver_role TEXT NOT NULL,
          target_id TEXT NOT NULL,
          action_type TEXT NOT NULL,
          control_plane_generation INTEGER NOT NULL DEFAULT 1,
          key_id TEXT,
          reason TEXT,
          issued_at_ms INTEGER NOT NULL,
          expires_at_ms INTEGER NOT NULL,
          consumed INTEGER NOT NULL DEFAULT 0,
          consumed_by_operator_id TEXT,
          consumed_at TEXT,
          revoked INTEGER NOT NULL DEFAULT 0,
          revoked_at TEXT,
          revocation_reason TEXT,
          signature_hmac_sha256 TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS atlas_control_plane_state (
          state_key TEXT PRIMARY KEY,
          state_value TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
      `);
      const apprCols = dbInstance.prepare("PRAGMA table_info('atlas_control_plane_approvals')").all();
      if (Array.isArray(apprCols) && apprCols.length > 0) {
        const apprNames = new Set(apprCols.map((c) => c.name));
        const requiredApprAdditions = [
          ['key_id', 'TEXT'],
          ['revoked', 'INTEGER NOT NULL DEFAULT 0'],
          ['revoked_at', 'TEXT'],
          ['revocation_reason', 'TEXT']
        ];
        for (const [col, def] of requiredApprAdditions) {
          if (!apprNames.has(col)) {
            dbInstance.exec(`ALTER TABLE atlas_control_plane_approvals ADD COLUMN ${col} ${def}`);
          }
        }
      }
    } catch (_) {}
  };

  const runBatch = () => {
    for (const mig of customMigrations) {
      failedVersion = mig.version;
      if (mig.version === 7) {
        ensureLegacyWarRoomColumns();
      }
      const checksum = crypto.createHash('sha256').update(mig.sql).digest('hex').slice(0, 32);
      if (!appliedMap.has(mig.version)) {
        dbInstance.exec(mig.sql);
        if (mig.version === 7) {
          ensureLegacyWarRoomColumns();
        }
        if (mig.version === 10) {
          ensureAtlasClosedLoopIncidentColumns();
        }
        insertMigration.run({
          version: mig.version,
          name: mig.name,
          checksum,
          applied_at: new Date().toISOString()
        });
        appliedCount++;
      } else {
        // Ensure tables still exist even if schema_migrations was previously populated
        dbInstance.exec(mig.sql);
        if (mig.version === 7) {
          ensureLegacyWarRoomColumns();
        }
        if (mig.version === 10) {
          ensureAtlasClosedLoopIncidentColumns();
        }
        const existing = appliedMap.get(mig.version);
        if (!existing || !existing.checksum) {
          dbInstance.prepare('UPDATE schema_migrations SET checksum = ? WHERE version = ?').run(checksum, mig.version);
        }
      }
    }
    failedVersion = null;
  };

  if (typeof dbInstance.transaction === 'function') {
    dbInstance.transaction(runBatch)();
  } else {
    dbInstance.exec('BEGIN IMMEDIATE;');
    try {
      runBatch();
      dbInstance.exec('COMMIT;');
    } catch (err) {
      try { dbInstance.exec('ROLLBACK;'); } catch (_) {}
      err.failedMigrationVersion = failedVersion;
      throw err;
    }
  }

  return {
    status: 'SUCCESS',
    appliedCount,
    totalMigrations: customMigrations.length,
    migrations: dbInstance.prepare('SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version ASC').all()
  };
}

module.exports = {
  MIGRATIONS,
  runMigrations
};
