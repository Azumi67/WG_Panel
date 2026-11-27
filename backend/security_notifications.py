def bind_security_html_escape(_panel_context):
    def _security_html_escape(value) -> str:
        import html

        return html.escape(
            str(value or ''),
            quote=True,
        )


    def _request_client_ip() -> tuple[str, str]:
        direct = _panel_context._http_security_direct_ip()
        effective = _panel_context._http_security_effective_ip()
        return effective, direct if direct != effective else ''


    def _request_device_summary() -> tuple[str, str]:

        user_agent = (
            _panel_context.request.headers.get('User-Agent')
            or 'unknown'
        ).strip()

        lower = user_agent.lower()

        if 'edg/' in lower:
            browser = 'Microsoft Edge'

        elif 'opr/' in lower or 'opera' in lower:
            browser = 'Opera'

        elif 'firefox/' in lower:
            browser = 'Firefox'

        elif 'chrome/' in lower or 'crios/' in lower:
            browser = 'Chrome'

        elif 'safari/' in lower:
            browser = 'Safari'

        else:
            browser = 'Unknown browser'

        if 'windows nt' in lower:
            operating_system = 'Windows'

        elif 'android' in lower:
            operating_system = 'Android'

        elif (
            'iphone' in lower
            or 'ipad' in lower
            or 'ios' in lower
        ):
            operating_system = 'iOS/iPadOS'

        elif (
            'mac os x' in lower
            or 'macintosh' in lower
        ):
            operating_system = 'macOS'

        elif 'linux' in lower:
            operating_system = 'Linux'

        else:
            operating_system = 'Unknown OS'

        return (
            f'{browser} · {operating_system}',
            user_agent[:500],
        )


    def _security_notify_enabled(event_type: str) -> bool:
        settings = _panel_context._load_tg_settings()

        if not settings.get('enabled'):
            return False

        notify = settings.get('notify') or {}

        if event_type == 'login_success':
            return bool(notify.get('login_success', True))

        if event_type in {'login_failed', 'twofa_failed'}:
            return bool(notify.get('login_fail', True))

        return False


    def _send_security_notification(
        event_type: str,
        username: str = '',
        reason: str = '',
    ) -> None:

        if not _panel_context._security_notify_enabled(
            event_type
        ):
            return


        client_ip, proxy_chain = (
            _panel_context._request_client_ip()
        )

        device_summary, raw_user_agent = (
            _panel_context._request_device_summary()
        )

        username = (
            username
            or 'unknown'
        ).strip()[:120]

        reason = (
            reason
            or ''
        ).strip()[:300]

        client_ip = (
            client_ip
            or 'unknown'
        ).strip()[:128]

        proxy_chain = (
            proxy_chain
            or ''
        ).strip()[:400]

        device_summary = (
            device_summary
            or 'Unknown device'
        ).strip()[:200]

        raw_user_agent = (
            raw_user_agent
            or ''
        ).strip()[:500]

        panel_host = (
            _panel_context.request.host
            or 'unknown'
        ).strip()[:255]

        scheme = (
            'HTTPS'
            if _panel_context._is_https()
            else 'HTTP'
        )

        if event_type == 'login_success':
            event_key = (
                'login_success'
            )

            title = (
                'Panel login accepted'
            )

            status = (
                'Authenticated'
            )

            dedupe_seconds = 0

        elif event_type == 'twofa_failed':
            event_key = (
                'login_fail'
            )

            title = (
                'Two-factor verification rejected'
            )

            status = (
                'Access denied'
            )

            dedupe_seconds = 10

        elif event_type == 'login_failed':
            event_key = (
                'login_fail'
            )

            title = (
                'Panel login rejected'
            )

            status = (
                'Access denied'
            )

            dedupe_seconds = 10

        else:

            _panel_context.current_app.logger.debug(
                'Unknown security notification event: %s',
                event_type,
            )

            return


        details = [
            (
                'Account',
                username,
            ),
            (
                'Client IP',
                client_ip,
            ),
            (
                'Device',
                device_summary,
            ),
            (
                'Panel address',
                (
                    f'{panel_host} · {scheme}'
                ),
            ),
        ]

        if reason:
            details.append(
                (
                    'Reason',
                    reason,
                )
            )

        if (
            proxy_chain
            and proxy_chain != client_ip
        ):
            details.append(
                (
                    'Proxy chain',
                    proxy_chain,
                )
            )

        if raw_user_agent:
            details.append(
                (
                    'User agent',
                    raw_user_agent,
                )
            )

        _panel_context._send_telegram_event(
            event_key,
            title,
            status=status,
            details=details,

            dedupe_key=(
                f'{event_type}:'
                f'{client_ip}:'
                f'{username}:'
                f'{reason}'
            ),

            dedupe_seconds=(
                dedupe_seconds
            ),
        )

    return {
        '_security_html_escape': _security_html_escape,
        '_request_client_ip': _request_client_ip,
        '_request_device_summary': _request_device_summary,
        '_security_notify_enabled': _security_notify_enabled,
        '_send_security_notification': _send_security_notification,
    }
