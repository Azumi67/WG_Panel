def bind_admin_columns(_panel_context):
    def _admin_columns():
        insp = _panel_context.inspect(_panel_context.db.engine)
        if not insp.has_table('admin_account'):
            _panel_context.db.create_all()
            return

        cols = {c['name'] for c in insp.get_columns('admin_account')}
        to_add = []
        if 'totp_secret' not in cols:
            to_add.append(("totp_secret", "TEXT"))
        if 'recovery_codes' not in cols:
            to_add.append(("recovery_codes", "TEXT"))
        if 'twofa_enabled' not in cols:
            to_add.append(("twofa_enabled", "INTEGER DEFAULT 0"))
        if 'last_totp_counter' not in cols:
            to_add.append(("last_totp_counter", "INTEGER DEFAULT 0"))
        if 'session_revision' not in cols:
            to_add.append(("session_revision", "INTEGER NOT NULL DEFAULT 0"))

        if to_add:
            with _panel_context.db.engine.begin() as conn:
                for name, typ in to_add:
                    conn.execute(_panel_context.text(f'ALTER TABLE admin_account ADD COLUMN {name} {typ}'))


    def _migrate_shortlinks_json_to_db():
        legacy_file = _panel_context.os.path.join(_panel_context.app.instance_path, "short_links.json")

        if not _panel_context.os.path.isfile(legacy_file):
            return

        try:
            with open(legacy_file, "r", encoding="utf-8") as f:
                old = _panel_context.json.load(f)
        except Exception:
            _panel_context.app.logger.exception("Could not read legacy short_links.json")
            return

        if not isinstance(old, dict):
            return

        imported = 0
        skipped = 0

        for token, rec in old.items():
            token = (token or "").strip()

            if not token or not isinstance(rec, dict):
                skipped += 1
                continue

            try:
                peer_id = int(rec.get("peer_id") or 0)
            except Exception:
                peer_id = 0

            if peer_id <= 0:
                skipped += 1
                continue

            peer = _panel_context.db.session.get(_panel_context.Peer, peer_id)
            if not peer:
                skipped += 1
                continue

            existing_token = _panel_context.ShortLink.query.filter_by(token=token).first()
            if existing_token:
                skipped += 1
                continue

            existing_peer = _panel_context.ShortLink.query.filter_by(peer_id=peer_id).first()
            if existing_peer:
                skipped += 1
                continue

            _panel_context.db.session.add(_panel_context.ShortLink(token=token, peer_id=peer_id))
            imported += 1

        if imported:
            _panel_context.db.session.commit()

        try:
            migrated_path = legacy_file + ".migrated"
            if not _panel_context.os.path.exists(migrated_path):
                _panel_context.os.replace(legacy_file, migrated_path)
        except Exception:
            _panel_context.app.logger.warning("Could not rename migrated short_links.json", exc_info=True)

        _panel_context.app.logger.info(
            "Shortlink migration finished: imported=%s skipped=%s",
            imported,
            skipped,
        )

    return {
        '_admin_columns': _admin_columns,
        '_migrate_shortlinks_json_to_db': _migrate_shortlinks_json_to_db,
    }


def bind_shortlink_schema(_panel_context):
    def _shortlink_schema():
        _panel_context.db.create_all()
        _panel_context._migrate_shortlinks_json_to_db()


    def _peer_schema():
        insp = _panel_context.inspect(_panel_context.db.engine)

        if not insp.has_table('peer'):
            return

        statements = []

        peer_cols = {c['name'] for c in insp.get_columns('peer')}
        if 'address_host' not in peer_cols:
            statements.append('ALTER TABLE peer ADD COLUMN address_host VARCHAR(64)')
        if 'peer_endpoint' not in peer_cols:
            statements.append('ALTER TABLE peer ADD COLUMN peer_endpoint VARCHAR(128)')
        if 'timer_started_at' not in peer_cols:
            statements.append('ALTER TABLE peer ADD COLUMN timer_started_at TIMESTAMP')

        if insp.has_table('subscription'):
            subscription_cols = {
                c['name'] for c in insp.get_columns('subscription')
            }
            if 'timer_started_at' not in subscription_cols:
                statements.append(
                    'ALTER TABLE subscription ADD COLUMN timer_started_at TIMESTAMP'
                )

        if insp.has_table('subscription_peer'):
            link_cols = {c['name'] for c in insp.get_columns('subscription_peer')}
            if 'owned' not in link_cols:
                statements.append(
                    'ALTER TABLE subscription_peer '
                    'ADD COLUMN owned BOOLEAN NOT NULL DEFAULT FALSE'
                )

        if statements:
            with _panel_context.db.engine.begin() as conn:
                for sql in statements:
                    conn.execute(_panel_context.text(sql))

        _panel_context._backfill_peer_address_hosts()


    def _backfill_peer_address_hosts():

        pending = (
            _panel_context.db.session.query(_panel_context.Peer)
            .filter(_panel_context.or_(_panel_context.Peer.address_host.is_(None), _panel_context.Peer.address_host == ''))
            .all()
        )
        for peer in pending:
            peer.address_host = _panel_context.peer_address_host(peer.address)

        if pending:
            _panel_context.db.session.commit()

        duplicates = (
            _panel_context.db.session.query(_panel_context.Peer.iface_id, _panel_context.Peer.address_host, _panel_context.func.count(_panel_context.Peer.id))
            .filter(_panel_context.Peer.address_host.isnot(None))
            .group_by(_panel_context.Peer.iface_id, _panel_context.Peer.address_host)
            .having(_panel_context.func.count(_panel_context.Peer.id) > 1)
            .all()
        )

        if duplicates:
            resolved = 0
            for iface_id, host, _count in duplicates:
                dup_peers = (
                    _panel_context.db.session.query(_panel_context.Peer.id)
                    .filter(_panel_context.Peer.iface_id == iface_id, _panel_context.Peer.address_host == host)
                    .order_by(_panel_context.Peer.id.asc())
                    .all()
                )
                loser_ids = [pid for (pid,) in dup_peers[1:]]
                if loser_ids:
                    _panel_context.db.session.query(_panel_context.Peer).filter(_panel_context.Peer.id.in_(loser_ids)).update(
                        {_panel_context.Peer.address_host: None}, synchronize_session=False
                    )
                    resolved += len(loser_ids)
            _panel_context.db.session.commit()
            _panel_context.app.logger.warning(
                "Resolved %s duplicate peer address_host row(s) by blanking the "
                "newer duplicates (their `address` column is unchanged). "
                "Duplicates were: %s",
                resolved,
                '; '.join(
                    f'iface_id={iface_id} address={host} peers={count}'
                    for iface_id, host, count in duplicates
                ),
            )

        if 'uq_peer_iface_address_host' in {ix['name'] for ix in _panel_context.inspect(_panel_context.db.engine).get_indexes('peer')}:
            return

        try:
            with _panel_context.db.engine.begin() as conn:
                conn.execute(_panel_context.text(
                    'CREATE UNIQUE INDEX uq_peer_iface_address_host '
                    'ON peer (iface_id, address_host)'
                ))
        except Exception:
            _panel_context.app.logger.debug("Peer address uniqueness index not created", exc_info=True)


    def _interface_schema():

        insp = _panel_context.inspect(_panel_context.db.engine)

        if not insp.has_table('interface_config'):
            return

        cols = {c['name'] for c in insp.get_columns('interface_config')}
        statements = []

        if 'endpoint_host' not in cols:
            statements.append(
                'ALTER TABLE interface_config ADD COLUMN endpoint_host VARCHAR(255)'
            )
        if 'endpoint_port' not in cols:
            statements.append(
                'ALTER TABLE interface_config ADD COLUMN endpoint_port INTEGER'
            )
        if 'public_key' not in cols:
            statements.append(
                'ALTER TABLE interface_config ADD COLUMN public_key VARCHAR(128)'
            )

        if statements:
            with _panel_context.db.engine.begin() as conn:
                for sql in statements:
                    conn.execute(_panel_context.text(sql))

    return {
        '_shortlink_schema': _shortlink_schema,
        '_peer_schema': _peer_schema,
        '_backfill_peer_address_hosts': _backfill_peer_address_hosts,
        '_interface_schema': _interface_schema,
    }


def bind_latest_peer_timer_event_ts(_panel_context):
    def _latest_peer_timer_event_ts(peer_id, event_names, *, details_needles=()):
        try:
            rows = (
                _panel_context.PeerEvent.query
                .filter(_panel_context.PeerEvent.peer_id == int(peer_id))
                .filter(_panel_context.PeerEvent.event.in_(tuple(event_names)))
                .order_by(_panel_context.PeerEvent.timestamp.desc())
                .limit(20)
                .all()
            )
        except Exception:
            return None

        for row in rows:
            if details_needles:
                details = str(getattr(row, 'details', '') or '').lower()
                if not any(needle in details for needle in details_needles):
                    continue
            timestamp = _panel_context.to_ts(getattr(row, 'timestamp', None))
            if timestamp:
                return timestamp
        return None


    def _assign_repaired_expiry(record, expected_ts):
        current_ts = _panel_context.to_ts(getattr(record, 'expires_at', None))
        if expected_ts is None:
            if current_ts is None:
                return False
            record.expires_at = None
            return True

        expected_ts = int(expected_ts)
        if current_ts is not None and abs(int(current_ts) - expected_ts) <= 2:
            return False

        record.expires_at = _panel_context.from_ts(expected_ts)
        return True


    def _repair_legacy_timer_rows():
        repaired_peers = 0
        repaired_subscriptions = 0

        try:
            if (
                _panel_context.db.engine.dialect.name == 'sqlite' and _panel_context.os.path.isfile(_panel_context.DB_PATH)
                and not _panel_context.os.path.exists(_panel_context._TIME_REPAIR_BACKUP)
            ):
                from reseller_portal.database import copy_database
                copy_database(_panel_context.DB_PATH, _panel_context._TIME_REPAIR_BACKUP)
        except Exception:
            _panel_context.app.logger.warning(
                'Could not create pre-time-fix database backup',
                exc_info=True,
            )

        for peer in _panel_context.Peer.query.order_by(_panel_context.Peer.id.asc()).all():
            if list(getattr(peer, 'subscription_links', []) or []):
                continue

            try:
                duration_days = float(getattr(peer, 'time_limit_days', 0) or 0)
            except (TypeError, ValueError, OverflowError):
                duration_days = 0.0

            expected_ts = None
            anchor_ts = None
            if not bool(getattr(peer, 'unlimited', False)) and duration_days > 0:
                if bool(getattr(peer, 'start_on_first_use', False)):
                    anchor_ts = _panel_context.to_ts(getattr(peer, 'first_used_at', None))
                else:
                    anchor_ts = _panel_context.to_ts(getattr(peer, 'created_at', None))

                    restarted_ts = _panel_context._latest_peer_timer_event_ts(
                        peer.id,
                        ('enabled', 'reset_timer'),
                    )
                    edited_ts = _panel_context._latest_peer_timer_event_ts(
                        peer.id,
                        ('edited',),
                        details_needles=(
                            'time_limit_days',
                            'start_on_first_use',
                            'unlimited',
                        ),
                    )
                    anchor_ts = max(
                        [value for value in (anchor_ts, restarted_ts, edited_ts) if value]
                        or [0]
                    ) or None

                expected_ts = _panel_context.add_days_ts(anchor_ts, duration_days)

            if _panel_context.to_ts(getattr(peer, 'timer_started_at', None)) != anchor_ts:
                peer.timer_started_at = _panel_context.from_ts(anchor_ts)
                repaired_peers += 1

            if _panel_context._assign_repaired_expiry(peer, expected_ts):
                repaired_peers += 1

            if (
                expected_ts
                and expected_ts <= _panel_context.now_ts()
                and str(getattr(peer, 'status', '') or '') == 'blocked'
            ):
                latest_expired = (
                    _panel_context.PeerEvent.query
                    .filter_by(peer_id=peer.id, event='expired')
                    .order_by(_panel_context.PeerEvent.timestamp.desc())
                    .first()
                )
                if (
                    latest_expired
                    and (_panel_context.to_ts(getattr(latest_expired, 'timestamp', None)) or 0)
                    >= int(anchor_ts or 0)
                ):
                    corrected_detail = f'Expired at {_panel_context.isoz(_panel_context.from_ts(expected_ts))}'
                    if str(latest_expired.details or '') != corrected_detail:
                        latest_expired.details = corrected_detail
                        repaired_peers += 1

        for sub in _panel_context.Subscription.query.order_by(_panel_context.Subscription.id.asc()).all():
            try:
                duration_days = float(getattr(sub, 'time_limit_days', 0) or 0)
            except (TypeError, ValueError, OverflowError):
                duration_days = 0.0

            expected_ts = None
            anchor_ts = None
            if not bool(getattr(sub, 'unlimited', False)) and duration_days > 0:
                if bool(getattr(sub, 'start_on_first_use', False)):
                    anchor_ts = _panel_context.to_ts(getattr(sub, 'first_used_at', None))
                else:
                    anchor_ts = _panel_context.to_ts(getattr(sub, 'created_at', None))
                    peer_ids = [
                        int(link.peer_id)
                        for link in (getattr(sub, 'links', []) or [])
                        if getattr(link, 'peer_id', None)
                    ]
                    if peer_ids:
                        reset_event = (
                            _panel_context.PeerEvent.query
                            .filter(_panel_context.PeerEvent.peer_id.in_(peer_ids))
                            .filter(_panel_context.PeerEvent.event == 'subscription_reset_timer')
                            .order_by(_panel_context.PeerEvent.timestamp.desc())
                            .first()
                        )
                        reset_ts = _panel_context.to_ts(
                            getattr(reset_event, 'timestamp', None)
                        ) if reset_event else None
                        if reset_ts:
                            anchor_ts = max(anchor_ts or 0, reset_ts)

                expected_ts = _panel_context.add_days_ts(anchor_ts, duration_days)

            if _panel_context.to_ts(getattr(sub, 'timer_started_at', None)) != anchor_ts:
                sub.timer_started_at = _panel_context.from_ts(anchor_ts)
                repaired_subscriptions += 1

            if _panel_context._assign_repaired_expiry(sub, expected_ts):
                repaired_subscriptions += 1

            for link in (getattr(sub, 'links', []) or []):
                peer = getattr(link, 'peer', None)
                if not peer:
                    continue
                peer_changed = False
                desired_days = duration_days or None
                desired_start = bool(getattr(sub, 'start_on_first_use', False))
                desired_unlimited = bool(getattr(sub, 'unlimited', False))
                desired_first_used = getattr(sub, 'first_used_at', None)
                desired_timer_started = getattr(sub, 'timer_started_at', None)

                if getattr(peer, 'time_limit_days', None) != desired_days:
                    peer.time_limit_days = desired_days
                    peer_changed = True
                if bool(getattr(peer, 'start_on_first_use', False)) != desired_start:
                    peer.start_on_first_use = desired_start
                    peer_changed = True
                if bool(getattr(peer, 'unlimited', False)) != desired_unlimited:
                    peer.unlimited = desired_unlimited
                    peer_changed = True
                if _panel_context.to_ts(getattr(peer, 'first_used_at', None)) != _panel_context.to_ts(desired_first_used):
                    peer.first_used_at = desired_first_used
                    peer_changed = True
                if _panel_context.to_ts(getattr(peer, 'timer_started_at', None)) != _panel_context.to_ts(desired_timer_started):
                    peer.timer_started_at = desired_timer_started
                    peer_changed = True
                if _panel_context._assign_repaired_expiry(peer, expected_ts):
                    peer_changed = True

                if peer_changed:
                    repaired_peers += 1

        if repaired_peers or repaired_subscriptions:
            _panel_context.db.session.commit()
            _panel_context.app.logger.warning(
                'Canonical UTC timer repair completed: peers=%s subscriptions=%s',
                repaired_peers,
                repaired_subscriptions,
            )
        else:
            _panel_context.db.session.rollback()

        return {
            'peers': repaired_peers,
            'subscriptions': repaired_subscriptions,
        }


    def _migrate_schema():
        from reseller_portal.database import schema_lock
        with schema_lock(_panel_context.db.engine):
            return _panel_context._migrate_schema_locked()


    def _migrate_schema_locked():
        try:
            _panel_context.db.create_all()
            _panel_context._admin_columns()
            _panel_context._peer_schema()
            _panel_context._interface_schema()
            _panel_context._shortlink_schema()
            _panel_context._repair_legacy_timer_rows()
        except Exception as exc:
            raise _panel_context.SchemaMigrationError(str(exc)) from exc

        _panel_context.app.logger.info("DB initialized / migrated OK")

    return {
        '_latest_peer_timer_event_ts': _latest_peer_timer_event_ts,
        '_assign_repaired_expiry': _assign_repaired_expiry,
        '_repair_legacy_timer_rows': _repair_legacy_timer_rows,
        '_migrate_schema': _migrate_schema,
        '_migrate_schema_locked': _migrate_schema_locked,
    }
