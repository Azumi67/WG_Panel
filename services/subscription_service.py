import re
from panel_core.customer_timers import _effective_expiry_ts, now_ts


SUBSCRIPTION_LAYOUTS = {
    'ps5',
    'mac',
    'app',
    'compact',
    'minimal',
    'showcase',
}

SUBSCRIPTION_LAYOUT_ALIASES = {
    'aurora': 'ps5',
    'cards': 'mac',
    'console': 'app',
    'split': 'showcase',
    'profile': 'showcase',
    'executive': 'mac',
    'flow': 'minimal',
}

def _sub_bool(v):
    if isinstance(v, bool):
        return v

    if v is None:
        return False

    return str(v).strip().lower() in {
        '1',
        'true',
        'yes',
        'on',
    }

def _sub_float(v, default=0.0):
    try:
        return float(v or default)
    except Exception:
        return float(default)

def _sub_int(v, default=0):
    try:
        return int(float(v or default))
    except Exception:
        return int(default)

def _subscription_settings_default():
    return {

        'layout': 'ps5',

        'hero_style': 'banner',
        'page_width': 'wide',
        'density': 'comfortable',

        'config_style': 'cards',
        'config_columns': 'two',
        'section_order': 'usage_first',

        'module_order': [
            'configs',
            'usage',
            'install',
            'support',
        ],
        'module_enabled': {
            'configs': True,
            'usage': True,
            'install': True,
            'support': True,
        },

        'module_sizes': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },

        'module_mobile': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },

        'module_surface': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },

                'module_spacing': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },


        'module_radius': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },


        'module_heading': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },

        'module_mobile_position': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },

        'module_gap': 'standard',

        'background': 'orbits',
        'accent': 'violet',

        'primary_color': '#7661ed',
        'secondary_color': '#63a5ff',

        'online_color': '#568eff',
        'offline_color': '#94a3b8',
        'warning_color': '#f59e0b',
        'danger_color': '#ef4444',
        'pill_color': '#64748b',
        'action_color': '#7661ed',

        'theme_default': 'auto',

        'surface': 'glass',
        'radius': 'rounded',
        'shadow': 'deep',
        'button_style': 'solid',
        'font_scale': 'standard',
        'font_family': 'rounded',
        'background_pattern': 'none',

        'background_intensity': 86,
        'card_opacity': 82,

        'display_mode': 'hybrid',
        'stat_size': 'standard',

        'show_percentage': True,
        'show_used_detail': True,

        'animation': 'cinematic',
        'entrance_animation': 'stagger',
        'hover_animation': 'lift',
        'toast_style': 'pill',
        'toast_position': 'bottom_center',
        'toast_motion': 'slide',
        'toast_duration': 2200,
        'motion_speed': 125,
        'motion_intensity': 150,
        'particle_density': 90,

        'show_quick_stats': True,
        'show_install': True,
        'show_support': True,
        'show_live_badge': True,
        'show_status_badge': True,

        'show_location_country': True,
        'show_download_action': True,
        'show_copy_action': True,
        'show_theme_action': True,
        'show_section_descriptions': True,

        'show_admin_notice': False,

        'show_account_details': False,
        'show_connection_overview': False,

        'notice_title': 'Service notice',
        'notice_text': '',

        'notice_tone': 'info',
        'notice_style': 'banner',
        'notice_position': 'after_summary',

        'portal_label': 'Secure WireGuard portal',
        'portal_icon': 'fas fa-bolt',

        'portal_title': '',
        'portal_subtitle': (
            'Your account is ready. Install WireGuard, '
            'then scan QR or import a config.'
        ),

        'title_align': 'left',
        'logo_size': 'medium',

        'usage_title': 'Usage overview',
        'configs_title': 'Configs',
        'install_title': 'Install WireGuard',
        'support_title': 'Support',

        'support_style': 'buttons',

        'support': {
            'telegram': '',
            'whatsapp': '',
            'phone': '',
            'email': '',
            'website': '',
            'instagram': '',
        },
    }

def _subscription_portal_icons():
    return {
        'fas fa-bolt',
        'fas fa-shield-halved',
        'fas fa-store',
        'fas fa-crown',
        'fas fa-rocket',
        'fas fa-globe',
        'fas fa-headset',
        'fas fa-wifi',
        'fas fa-gamepad',
        'fas fa-server',
        'fas fa-link',
        'fas fa-signal',
        'fas fa-gem',
        'fas fa-building',
        'fas fa-cloud',
        'fas fa-network-wired',
        'fas fa-lock',
        'fas fa-star',
    }

def _subscription_portal_icon(value):
    value = str(
        value or ''
    ).strip()

    return (
        value
        if value in _subscription_portal_icons()
        else 'fas fa-bolt'
    )

def _subscription_text(
    value,
    default='',
    max_len=160,
):
    value = str(
        value or ''
    ).strip()

    if not value:
        return default

    return value[:max_len]

def _subscription_choice(
    value,
    allowed,
    default,
):
    value = str(
        value or ''
    ).strip().lower()

    return (
        value
        if value in allowed
        else default
    )

def _subscription_number(
    value,
    default,
    minimum,
    maximum,
):
    try:
        number = int(
            float(value)
        )
    except Exception:
        number = int(default)

    return max(
        minimum,
        min(
            maximum,
            number,
        ),
    )

def _normalize_subscription_settings(
    incoming=None,
    *,
    base=None,
):
    incoming = (
        incoming
        if isinstance(incoming, dict)
        else {}
    )

    defaults = (
        dict(base)
        if isinstance(base, dict)
        else _subscription_settings_default()
    )

    d = _subscription_settings_default()

    for key, value in defaults.items():
        if key == 'support':
            continue

        d[key] = value

    d['support'] = dict(
        defaults.get('support')
        or d['support']
    )


    layout = str(
        incoming.get('layout')
        or incoming.get('selected')
        or d['layout']
    ).strip().lower()


    layout = SUBSCRIPTION_LAYOUT_ALIASES.get(
        layout,
        layout,
    )

    d['layout'] = (
        layout
        if layout in SUBSCRIPTION_LAYOUTS
        else 'ps5'
    )

    d['hero_style'] = _subscription_choice(
        incoming.get(
            'hero_style',
            d['hero_style'],
        ),
        {
            'panel',
            'banner',
            'minimal',
        },
        'panel',
    )

    d['page_width'] = _subscription_choice(
        incoming.get(
            'page_width',
            d['page_width'],
        ),
        {
            'narrow',
            'standard',
            'wide',
        },
        'standard',
    )

    d['density'] = _subscription_choice(
        incoming.get(
            'density',
            d['density'],
        ),
        {
            'comfortable',
            'compact',
        },
        'comfortable',
    )

    d['config_style'] = _subscription_choice(
        incoming.get(
            'config_style',
            d['config_style'],
        ),
        {
            'cards',
            'list',
            'compact',
        },
        'cards',
    )

    d['config_columns'] = _subscription_choice(
        incoming.get(
            'config_columns',
            d['config_columns'],
        ),
        {
            'auto',
            'one',
            'two',
        },
        'auto',
    )

    d['section_order'] = _subscription_choice(
        incoming.get(
            'section_order',
            d['section_order'],
        ),
        {
            'standard',
            'configs_first',
            'usage_first',
        },
        'standard',
    )

    allowed_modules = (
        'configs',
        'usage',
        'install',
        'support',
    )

    default_module_order = [
        'configs',
        'usage',
        'install',
        'support',
    ]

    incoming_module_order = incoming.get(
        'module_order',
        d.get(
            'module_order',
            default_module_order,
        ),
    )

    if not isinstance(
        incoming_module_order,
        (list, tuple),
    ):
        incoming_module_order = []

    normalized_module_order = []

    for module_name in incoming_module_order:
        module_name = str(
            module_name or ''
        ).strip().lower()

        if (
            module_name in allowed_modules
            and module_name
            not in normalized_module_order
        ):
            normalized_module_order.append(
                module_name
            )

    for module_name in default_module_order:
        if (
            module_name
            not in normalized_module_order
        ):
            normalized_module_order.append(
                module_name
            )

    d['module_order'] = (
        normalized_module_order[:4]
    )

    module_keys = (
        'configs',
        'usage',
        'install',
        'support',
    )

    current_enabled = (
        d.get('module_enabled')
        if isinstance(
            d.get('module_enabled'),
            dict,
        )
        else {}
    )

    incoming_enabled = (
        incoming.get('module_enabled')
        if isinstance(
            incoming.get('module_enabled'),
            dict,
        )
        else {}
    )

    normalized_enabled = {}

    for module_name in module_keys:

        if module_name in incoming_enabled:
            value = incoming_enabled.get(
                module_name
            )
        else:
            value = current_enabled.get(
                module_name,
                True,
            )

        normalized_enabled[
            module_name
        ] = _sub_bool(
            value
        )

    if not any(
        normalized_enabled.values()
    ):
        normalized_enabled[
            'configs'
        ] = True

    d['module_enabled'] = (
        normalized_enabled
    )

    allowed_module_sizes = {
        'auto',
        'small',
        'medium',
        'large',
        'full',
    }

    current_sizes = (
        d.get('module_sizes')
        if isinstance(
            d.get('module_sizes'),
            dict,
        )
        else {}
    )

    incoming_sizes = (
        incoming.get('module_sizes')
        if isinstance(
            incoming.get('module_sizes'),
            dict,
        )
        else {}
    )

    normalized_sizes = {}

    for module_name in module_keys:

        value = str(
            incoming_sizes.get(
                module_name,
                current_sizes.get(
                    module_name,
                    'auto',
                ),
            )
            or 'auto'
        ).strip().lower()

        if value not in allowed_module_sizes:
            value = 'auto'

        normalized_sizes[
            module_name
        ] = value

    d['module_sizes'] = (
        normalized_sizes
    )

    allowed_mobile_sizes = {
        'auto',
        'half',
        'full',
    }

    current_mobile = (
        d.get('module_mobile')
        if isinstance(
            d.get('module_mobile'),
            dict,
        )
        else {}
    )

    incoming_mobile = (
        incoming.get('module_mobile')
        if isinstance(
            incoming.get('module_mobile'),
            dict,
        )
        else {}
    )

    normalized_mobile = {}

    for module_name in module_keys:

        value = str(
            incoming_mobile.get(
                module_name,
                current_mobile.get(
                    module_name,
                    'auto',
                ),
            )
            or 'auto'
        ).strip().lower()

        if value not in allowed_mobile_sizes:
            value = 'auto'

        normalized_mobile[
            module_name
        ] = value

    d['module_mobile'] = (
        normalized_mobile
    )

    allowed_surfaces = {
        'auto',
        'panel',
        'soft',
        'outline',
        'flat',
        'accent',
    }

    current_surfaces = (
        d.get('module_surface')
        if isinstance(
            d.get('module_surface'),
            dict,
        )
        else {}
    )

    incoming_surfaces = (
        incoming.get('module_surface')
        if isinstance(
            incoming.get('module_surface'),
            dict,
        )
        else {}
    )

    normalized_surfaces = {}

    for module_name in module_keys:

        value = str(
            incoming_surfaces.get(
                module_name,
                current_surfaces.get(
                    module_name,
                    'auto',
                ),
            )
            or 'auto'
        ).strip().lower()

        if value not in allowed_surfaces:
            value = 'auto'

        normalized_surfaces[
            module_name
        ] = value

    d['module_surface'] = (
        normalized_surfaces
    )

    allowed_spacing = {
        'auto',
        'compact',
        'comfortable',
        'roomy',
    }

    current_spacing = (
        d.get('module_spacing')
        if isinstance(
            d.get('module_spacing'),
            dict,
        )
        else {}
    )

    incoming_spacing = (
        incoming.get('module_spacing')
        if isinstance(
            incoming.get('module_spacing'),
            dict,
        )
        else {}
    )

    normalized_spacing = {}

    for module_name in module_keys:

        value = str(
            incoming_spacing.get(
                module_name,
                current_spacing.get(
                    module_name,
                    'auto',
                ),
            )
            or 'auto'
        ).strip().lower()

        if value not in allowed_spacing:
            value = 'auto'

        normalized_spacing[
            module_name
        ] = value

    d['module_spacing'] = (
        normalized_spacing
    )

    def normalize_module_option_map(
        setting_key,
        allowed_values,
        default_value='auto',
        *,
        unique_non_default=False,
    ):
        current_values = (
            d.get(setting_key)
            if isinstance(
                d.get(setting_key),
                dict,
            )
            else {}
        )

        incoming_values = (
            incoming.get(setting_key)
            if isinstance(
                incoming.get(setting_key),
                dict,
            )
            else {}
        )

        normalized_values = {}
        used_values = set()

        for module_name in module_keys:

            value = str(
                incoming_values.get(
                    module_name,
                    current_values.get(
                        module_name,
                        default_value,
                    ),
                )
                or default_value
            ).strip().lower()

            if value not in allowed_values:
                value = default_value

            if (
                unique_non_default
                and value != default_value
            ):
                if value in used_values:
                    value = default_value
                else:
                    used_values.add(
                        value
                    )

            normalized_values[
                module_name
            ] = value

        return normalized_values


    d['module_radius'] = (
        normalize_module_option_map(
            'module_radius',
            {
                'auto',
                'square',
                'soft',
                'round',
            },
        )
    )


    d['module_heading'] = (
        normalize_module_option_map(
            'module_heading',
            {
                'auto',
                'standard',
                'compact',
                'accent',
                'hidden',
            },
        )
    )

    d['module_mobile_position'] = (
        normalize_module_option_map(
            'module_mobile_position',
            {
                'auto',
                '1',
                '2',
                '3',
                '4',
            },
            unique_non_default=True,
        )
    )

    d['module_gap'] = _subscription_choice(
        incoming.get(
            'module_gap',
            d.get(
                'module_gap',
                'auto',
            ),
        ),
        {
            'auto',
            'tight',
            'standard',
            'roomy',
        },
        'auto',
    )

    d['background'] = _subscription_choice(
        incoming.get(
            'background',
            d['background'],
        ),
        {
            'aurora',
            'waves',
            'network',
            'orbits',
            'mesh',
            'nebula',
            'lines',
            'constellation',
            'prism',
            'circuit',
            'pulse',
            'none',
        },
        'aurora',
    )

    d['accent'] = _subscription_choice(
        incoming.get(
            'accent',
            d['accent'],
        ),
        {
            'mint',
            'blue',
            'violet',
            'coral',
            'amber',
            'mono',
            'custom',
        },
        'violet',
    )

    d['theme_default'] = _subscription_choice(
        incoming.get(
            'theme_default',
            d['theme_default'],
        ),
        {
            'auto',
            'light',
            'dark',
        },
        'auto',
    )

    d['surface'] = _subscription_choice(
        incoming.get(
            'surface',
            d['surface'],
        ),
        {
            'glass',
            'solid',
            'soft',
        },
        'glass',
    )

    d['radius'] = _subscription_choice(
        incoming.get(
            'radius',
            d['radius'],
        ),
        {
            'rounded',
            'medium',
            'square',
        },
        'rounded',
    )

    d['shadow'] = _subscription_choice(
        incoming.get(
            'shadow',
            d['shadow'],
        ),
        {
            'none',
            'soft',
            'deep',
        },
        'soft',
    )

    d['button_style'] = _subscription_choice(
        incoming.get(
            'button_style',
            d['button_style'],
        ),
        {
            'solid',
            'outline',
            'soft',
        },
        'solid',
    )

    d['font_scale'] = _subscription_choice(
        incoming.get(
            'font_scale',
            d['font_scale'],
        ),
        {
            'small',
            'standard',
            'large',
        },
        'standard',
    )

    d['font_family'] = _subscription_choice(incoming.get('font_family', d.get('font_family', 'rounded')), {'rounded', 'system', 'humanist'}, 'rounded')
    d['background_pattern'] = _subscription_choice(incoming.get('background_pattern', d.get('background_pattern', 'none')), {'none', 'grid', 'dots'}, 'none')

    color_fields = (
        ('primary_color', 'custom_primary', '#7661ed'),
        ('secondary_color', 'custom_secondary', '#63a5ff'),
        ('online_color', None, '#568eff'),
        ('offline_color', None, '#94a3b8'),
        ('warning_color', None, '#f59e0b'),
        ('danger_color', None, '#ef4444'),
        ('pill_color', None, '#64748b'),
        ('action_color', None, '#7661ed'),
    )

    for key, legacy_key, fallback in color_fields:
        candidate = incoming.get(key)

        if candidate in (None, '') and legacy_key:
            candidate = incoming.get(legacy_key)

        if candidate in (None, ''):
            candidate = d.get(key) or fallback

        value = str(candidate or '').strip()

        if not re.fullmatch(r'#[0-9A-Fa-f]{6}', value):
            value = fallback

        d[key] = value.lower()

    d['background_intensity'] = (
        _subscription_number(
            incoming.get(
                'background_intensity',
                d['background_intensity'],
            ),
            86,
            0,
            100,
        )
    )

    d['card_opacity'] = (
        _subscription_number(
            incoming.get(
                'card_opacity',
                d['card_opacity'],
            ),
            82,
            50,
            100,
        )
    )

    d['display_mode'] = _subscription_choice(
        incoming.get(
            'display_mode',
            incoming.get(
                'stats_style',
                d['display_mode'],
            ),
        ),
        {
            'bars',
            'rings',
            'hybrid',
            'focus',
            'minimal',
            'segments',
        },
        'hybrid',
    )

    d['stat_size'] = _subscription_choice(
        incoming.get(
            'stat_size',
            d['stat_size'],
        ),
        {
            'compact',
            'standard',
            'large',
        },
        'standard',
    )

    d['animation'] = _subscription_choice(
        incoming.get(
            'animation',
            incoming.get(
                'motion',
                d['animation'],
            ),
        ),
        {
            'cinematic',
            'immersive',
            'rich',
            'balanced',
            'soft',
            'drift',
            'minimal',
            'off',
        },
        'cinematic',
    )

    d['entrance_animation'] = _subscription_choice(
        incoming.get(
            'entrance_animation',
            d['entrance_animation'],
        ),
        {'stagger', 'slide', 'fade', 'scale', 'none'},
        'stagger',
    )

    d['hover_animation'] = _subscription_choice(
        incoming.get(
            'hover_animation',
            d['hover_animation'],
        ),
        {'lift', 'glow', 'scale', 'none'},
        'lift',
    )

    d['toast_style'] = _subscription_choice(
        incoming.get('toast_style', d['toast_style']),
        {'pill', 'card', 'glass', 'terminal', 'minimal'},
        'pill',
    )

    d['toast_position'] = _subscription_choice(
        incoming.get('toast_position', d['toast_position']),
        {'bottom_center', 'bottom_right', 'top_right', 'top_center'},
        'bottom_center',
    )

    d['toast_motion'] = _subscription_choice(
        incoming.get('toast_motion', d['toast_motion']),
        {'slide', 'pop', 'fade', 'bounce'},
        'slide',
    )

    d['toast_duration'] = _subscription_number(
        incoming.get('toast_duration', d['toast_duration']),
        2200,
        1200,
        6000,
    )

    d['motion_speed'] = _subscription_number(
        incoming.get('motion_speed', d['motion_speed']),
        125,
        50,
        180,
    )

    d['motion_intensity'] = _subscription_number(
        incoming.get('motion_intensity', d['motion_intensity']),
        150,
        40,
        200,
    )

    d['particle_density'] = _subscription_number(
        incoming.get('particle_density', d['particle_density']),
        90,
        0,
        120,
    )

    for key in (
        'show_percentage',
        'show_used_detail',
        'show_quick_stats',
        'show_install',
        'show_support',
        'show_live_badge',
        'show_status_badge',
        'show_location_country',
        'show_download_action',
        'show_copy_action',
        'show_theme_action',
        'show_section_descriptions',
        'show_admin_notice',
        'show_account_details',
        'show_connection_overview',
    ):
        if key in incoming:
            d[key] = _sub_bool(
                incoming.get(key)
            )

    identity = (
        incoming.get('identity')
        if isinstance(
            incoming.get('identity'),
            dict,
        )
        else {}
    )

    public = (
        incoming.get('public')
        if isinstance(
            incoming.get('public'),
            dict,
        )
        else {}
    )

    def pick(
        *keys,
        default=None,
    ):
        for source in (
            incoming,
            identity,
            public,
        ):
            if not isinstance(
                source,
                dict,
            ):
                continue

            for key in keys:
                if key in source:
                    return source.get(key)

        return default

    d['portal_label'] = _subscription_text(
        pick(
            'portal_label',
            'badge_label',
            'label',
            default=d['portal_label'],
        ),
        d['portal_label'],
        80,
    )

    d['portal_icon'] = (
        _subscription_portal_icon(
            pick(
                'portal_icon',
                'badge_icon',
                'icon',
                default=d['portal_icon'],
            )
        )
    )

    d['portal_title'] = _subscription_text(
        pick(
            'portal_title',
            'title',
            default=d['portal_title'],
        ),
        '',
        90,
    )

    d['portal_subtitle'] = _subscription_text(
        pick(
            'portal_subtitle',
            'subtitle',
            default=d['portal_subtitle'],
        ),
        d['portal_subtitle'],
        180,
    )

    d['title_align'] = _subscription_choice(
        incoming.get(
            'title_align',
            d['title_align'],
        ),
        {
            'left',
            'center',
        },
        'left',
    )

    d['logo_size'] = _subscription_choice(
        incoming.get(
            'logo_size',
            d['logo_size'],
        ),
        {
            'small',
            'medium',
            'large',
        },
        'medium',
    )

    d['usage_title'] = _subscription_text(
        incoming.get(
            'usage_title',
            d['usage_title'],
        ),
        'Usage overview',
        80,
    )

    d['configs_title'] = _subscription_text(
        incoming.get(
            'configs_title',
            d['configs_title'],
        ),
        'Configs',
        80,
    )

    d['install_title'] = _subscription_text(
        incoming.get(
            'install_title',
            d['install_title'],
        ),
        'Install WireGuard',
        80,
    )

    d['support_title'] = _subscription_text(
        incoming.get(
            'support_title',
            d['support_title'],
        ),
        'Support',
        80,
    )

    d['notice_title'] = _subscription_text(
        incoming.get(
            'notice_title',
            d.get(
                'notice_title',
                'Service notice',
            ),
        ),
        'Service notice',
        60,
    )

    d['notice_text'] = _subscription_text(
        incoming.get(
            'notice_text',
            d.get(
                'notice_text',
                '',
            ),
        ),
        '',
        240,
    )
    d['notice_tone'] = _subscription_choice(
        incoming.get(
            'notice_tone',
            d.get(
                'notice_tone',
                'info',
            ),
        ),
        {
            'info',
            'maintenance',
            'warning',
            'success',
            'neutral',
        },
        'info',
    )

    d['notice_style'] = _subscription_choice(
        incoming.get(
            'notice_style',
            d.get(
                'notice_style',
                'banner',
            ),
        ),
        {
            'banner',
            'card',
            'strip',
        },
        'banner',
    )

    d['notice_position'] = _subscription_choice(
        incoming.get(
            'notice_position',
            d.get(
                'notice_position',
                'after_summary',
            ),
        ),
        {
            'after_summary',
            'before_modules',
            'after_modules',
        },
        'after_summary',
    )

    d['support_style'] = _subscription_choice(
        incoming.get(
            'support_style',
            d['support_style'],
        ),
        {
            'buttons',
            'list',
            'compact',
        },
        'buttons',
    )

    support = (
        incoming.get('support')
        if isinstance(
            incoming.get('support'),
            dict,
        )
        else {}
    )

    socials = (
        incoming.get('socials')
        if isinstance(
            incoming.get('socials'),
            dict,
        )
        else {}
    )

    existing_support = (
        d.get('support')
        or {}
    )

    normalized_support = {}

    for key in (
        'telegram',
        'whatsapp',
        'phone',
        'email',
        'website',
        'instagram',
    ):
        if key in support:
            value = support.get(key)

        elif key in socials:
            value = socials.get(key)

        else:
            value = existing_support.get(
                key,
                '',
            )

        normalized_support[key] = str(
            value or ''
        ).strip()[:500]

    d['support'] = normalized_support

    return d

def _sub_limit_bytes(sub):
    try:
        return sub.limit_bytes()
    except Exception:
        if not getattr(sub, 'data_limit_value', 0) or getattr(sub, 'unlimited', False):
            return None
        mult = 1024**2 if (getattr(sub, 'data_limit_unit', None) or 'Mi') == 'Mi' else 1024**3
        return int(sub.data_limit_value) * mult

def _sub_ttl_seconds(sub):
    exp_ts = _effective_expiry_ts(sub)
    return max(0, exp_ts - now_ts()) if exp_ts else None

def bind_services(*,
    InterfaceConfig,
    Node,
    Peer,
    SUBSCRIPTION_PORTAL_OVERRIDES_FILE,
    SUBSCRIPTION_SETTINGS_FILE,
    SubscriptionPeer,
    _accumulate_peer_usage,
    _check_iface_up,
    _clear_timer_cycle,
    _disable_peer,
    _effective_expiry_ts,
    _host_peer,
    _iface_up,
    _normalize_subscription_settings,
    _panel_display_datetime,
    _panel_timezone_name,
    _start_timer_cycle,
    _sub_bool,
    _sub_float,
    _sub_int,
    _sub_limit_bytes,
    _sub_ttl_seconds,
    _subscription_public_payload,
    _sync_effective_expiry,
    _sync_peer,
    _wg_disable,
    _wg_enable,
    _wg_runtime_snapshot,
    _wg_transfer,
    _write_json_atomic,
    abort,
    allocate_peer_address,
    app,
    current_app,
    datetime,
    db,
    effective_peer_state,
    ensure_node_mirror_iface,
    from_ts,
    g,
    iface_devname,
    install_local_peer,
    interface_allocation_lock,
    ipaddress,
    isoz,
    json,
    log_event,
    node_get,
    node_install_peer,
    node_post,
    now_ts,
    os,
    parse_endpoint_string,
    re,
    render_template,
    requested_peer_address_from_target,
    subprocess,
    subscription_access,
    to_ts,
    url_for,
):

    def _load_subscription_settings():
        os.makedirs(
            app.instance_path,
            exist_ok=True,
        )

        try:
            with open(
                SUBSCRIPTION_SETTINGS_FILE,
                'r',
                encoding='utf-8',
            ) as handle:
                payload = (
                    json.load(handle)
                    or {}
                )

        except Exception:
            payload = {}

        return _normalize_subscription_settings(
            payload
        )

    def _save_subscription_settings(data):
        current = (
            _load_subscription_settings()
        )

        saved = (
            _normalize_subscription_settings(
                data,
                base=current,
            )
        )

        _write_json_atomic(
            SUBSCRIPTION_SETTINGS_FILE,
            saved,
        )

        return saved

    def _load_subscription_portal_overrides():
        try:
            with open(
                SUBSCRIPTION_PORTAL_OVERRIDES_FILE,
                'r',
                encoding='utf-8',
            ) as handle:
                payload = (
                    json.load(handle)
                    or {}
                )

            return (
                payload
                if isinstance(payload, dict)
                else {}
            )

        except Exception:
            return {}

    def _save_subscription_portal_overrides(
        data,
    ):
        if not isinstance(data, dict):
            data = {}

        _write_json_atomic(
            SUBSCRIPTION_PORTAL_OVERRIDES_FILE,
            data,
        )

    def _subscription_portal_override(
        sub,
    ):
        if not sub:
            return {}

        store = (
            _load_subscription_portal_overrides()
        )

        value = store.get(
            str(
                getattr(
                    sub,
                    'id',
                    '',
                )
            )
        )

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    def _sub_used_bytes(sub):
        total = 0
        dirty = False

        for link in list(getattr(sub, 'links', []) or []):
            peer = getattr(link, 'peer', None)
            if not peer:
                continue

            try:
                iface = getattr(peer, 'iface', None)
                is_node = bool(
                    iface and (
                        getattr(iface, 'node_id', None) is not None or
                        re.match(r'^n\d+:', getattr(iface, 'name', '') or '')
                    )
                )

                if is_node:
                    used = int(getattr(peer, 'used_bytes_total', 0) or 0)
                else:
                    live = _wg_transfer(peer)
                    used, _delta, changed = _accumulate_peer_usage(peer, live)
                    if changed:
                        dirty = True

            except Exception:
                used = int(getattr(peer, 'used_bytes_total', 0) or 0)

            total += int(used or 0)

        if dirty:
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()

        return int(total)

    def _sub_public_url(sub):
        return url_for('subscription_public_page', token=sub.token, _external=True)

    def _sub_config_url(sub):
        return url_for('subscription_public_config', token=sub.token, _external=True)

    def _apply_subscription_timer(sub, *, restart=False):

        unlimited = bool(
            getattr(
                sub,
                'unlimited',
                False,
            )
        )

        days = _sub_float(
            getattr(
                sub,
                'time_limit_days',
                0,
            )
        )

        if unlimited or not days:
            _clear_timer_cycle(sub)
            return

        start_on_first_use = bool(
            getattr(
                sub,
                'start_on_first_use',
                False,
            )
        )

        if start_on_first_use:

            first_used_at = getattr(
                sub,
                'first_used_at',
                None,
            )

            if not first_used_at:
                _clear_timer_cycle(sub)
                return

            sub.timer_started_at = first_used_at
            _sync_effective_expiry(sub)

            return

        if restart:
            _start_timer_cycle(sub)
        else:
            if not getattr(sub, 'timer_started_at', None):
                sub.timer_started_at = (
                    getattr(sub, 'created_at', None)
                    or from_ts(now_ts())
                )
            _sync_effective_expiry(sub)

    def _sync_peer_subscription(peer, sub, idx=None, rename=True):
        if rename:
            total = len(getattr(sub, 'links', []) or []) or 1
            base = (sub.name or 'subscription').strip() or 'subscription'
            if idx is not None and total > 1:
                peer.name = f'{base}-{idx + 1}'
            else:
                peer.name = base
        peer.data_limit_value = int(getattr(sub, 'data_limit_value', 0) or 0)
        peer.data_limit_unit = getattr(sub, 'data_limit_unit', None) or 'Gi'
        peer.time_limit_days = _sub_float(getattr(sub, 'time_limit_days', 0)) or None
        peer.start_on_first_use = bool(getattr(sub, 'start_on_first_use', False))
        peer.unlimited = bool(getattr(sub, 'unlimited', False))
        peer.phone_number = getattr(sub, 'phone_number', '') or ''
        peer.telegram_id = getattr(sub, 'telegram_id', '') or ''
        peer.timer_started_at = getattr(sub, 'timer_started_at', None)
        peer.expires_at = getattr(sub, 'expires_at', None)
        return peer

    def _sync_all_subscription_peers(sub, rename=True):
        links = sorted(list(getattr(sub, 'links', []) or []), key=lambda l: (l.sort_order or 0, l.id or 0))
        for idx, link in enumerate(links):
            if link.peer:
                _sync_peer_subscription(link.peer, sub, idx=idx, rename=rename)

    def _block_subscription_runtime(sub, reason='subscription_blocked', recovery_pending=None, *, commit=True):
        from reseller_portal.models import Setting as ResellerSetting
        if recovery_pending is None:
            recovery_pending={int(row.key.split(':',1)[1]) for row in ResellerSetting.query.filter(ResellerSetting.key.like('recovery_pending:%')).all() if row.value is True}
        changed = False

        for link in list(getattr(sub, 'links', []) or []):
            peer = getattr(link, 'peer', None)
            if not peer or peer.id in recovery_pending:
                continue

            if getattr(peer, 'status', None) == 'blocked':
                continue

            ok = False
            try:
                ok = bool(_disable_peer(peer, reason, status='blocked', commit=commit))
            except Exception:
                ok = False

            if not ok:
                current_app.logger.warning('Subscription enforcement will retry peer %s: runtime disable was not confirmed.', peer.id)
                continue

            changed = True

        if changed and commit:
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()

        return changed

    def _subscription_peer_runtime(peer):

        iface = getattr(
            peer,
            'iface',
            None,
        )

        raw_iface_name = str(
            getattr(
                iface,
                'name',
                '',
            )
            or ''
        ).strip()

        public_key = str(
            getattr(
                peer,
                'public_key',
                '',
            )
            or ''
        ).strip()

        current_epoch = now_ts()

        try:
            handshake_window = max(
                30,
                int(
                    os.environ.get(
                        'WG_SUBSCRIPTION_CONNECTED_WINDOW',
                        '180',
                    )
                    or 180
                ),
            )

        except Exception:
            handshake_window = 180

        result = {
            'connected': False,

            'conn_status': 'offline',

            'connection_status': (
                'disconnected'
            ),

            'connection_label': (
                'Disconnected'
            ),

            'conn_reason': (
                'no_recent_activity'
            ),

            'latest_handshake': 0,

            'latest_handshake_age': None,

            'last_activity_at': None,

            'runtime_available': True,

            'handshake_window': (
                handshake_window
            ),
        }

        if (
            not iface
            or not public_key
        ):
            result[
                'runtime_available'
            ] = False

            result[
                'conn_reason'
            ] = 'peer_runtime_missing'

            return result

        node_id = getattr(
            iface,
            'node_id',
            None,
        )

        legacy_node_match = (
            re.match(
                r'^n(\d+):(.+)$',
                raw_iface_name,
            )
        )

        if (
            node_id is None
            and legacy_node_match
        ):
            try:
                node_id = int(
                    legacy_node_match.group(
                        1
                    )
                )
            except Exception:
                node_id = None

        is_node = bool(
            node_id is not None
            or legacy_node_match
        )

        if is_node:
            node = getattr(
                iface,
                'node',
                None,
            )

            if (
                node is None
                and node_id is not None
            ):
                node = db.session.get(
                    Node,
                    int(node_id),
                )

            if node is None:
                result[
                    'runtime_available'
                ] = False

                result[
                    'conn_reason'
                ] = 'node_missing'

                return result

            cache = getattr(
                g,
                '_subscription_node_runtime_cache',
                None,
            )

            if cache is None:
                cache = {}

                g._subscription_node_runtime_cache = (
                    cache
                )

            cache_key = int(
                node.id
            )

            if cache_key not in cache:
                try:
                    payload = (
                        node_get(
                            node,
                            '/api/peers',
                            timeout=2,
                        )
                        or {}
                    )

                    rows = (
                        payload.get(
                            'peers'
                        )
                        if isinstance(
                            payload,
                            dict,
                        )
                        else []
                    )

                    runtime_by_key = {}

                    for row in (
                        rows or []
                    ):
                        if not isinstance(
                            row,
                            dict,
                        ):
                            continue

                        row_public_key = str(
                            row.get(
                                'public_key'
                            )
                            or row.get(
                                'id'
                            )
                            or ''
                        ).strip()

                        if row_public_key:
                            runtime_by_key[
                                row_public_key
                            ] = row

                    cache[
                        cache_key
                    ] = {
                        'ok': True,
                        'rows': runtime_by_key,
                    }

                except Exception as exc:
                    current_app.logger.debug(
                        'Subscription runtime: node %s unavailable: %s',
                        getattr(
                            node,
                            'id',
                            '?',
                        ),
                        exc,
                    )

                    cache[
                        cache_key
                    ] = {
                        'ok': False,
                        'rows': {},
                    }

            node_cache = (
                cache.get(
                    cache_key
                )
                or {}
            )

            if not node_cache.get(
                'ok'
            ):
                result[
                    'runtime_available'
                ] = False

                result[
                    'conn_reason'
                ] = 'node_unavailable'

                return result

            row = (
                node_cache.get(
                    'rows'
                )
                or {}
            ).get(
                public_key
            )

            if not isinstance(
                row,
                dict,
            ):
                result[
                    'conn_reason'
                ] = 'peer_not_in_runtime'

                return result

            try:
                latest_handshake = max(
                    0,
                    int(
                        row.get(
                            'latest_handshake'
                        )
                        or 0
                    ),
                )

            except Exception:
                latest_handshake = 0

            try:
                handshake_age = (
                    row.get(
                        'latest_handshake_age'
                    )
                )

                if handshake_age is not None:
                    handshake_age = max(
                        0,
                        int(
                            handshake_age
                        ),
                    )

                elif latest_handshake > 0:
                    handshake_age = max(
                        0,
                        current_epoch
                        - latest_handshake,
                    )

                else:
                    handshake_age = None

            except Exception:
                handshake_age = (
                    max(
                        0,
                        current_epoch
                        - latest_handshake,
                    )
                    if latest_handshake > 0
                    else None
                )

            connected = bool(
                latest_handshake > 0
                and handshake_age is not None
                and handshake_age
                <= handshake_window
            )

            try:
                rx_mib = float(
                    row.get(
                        'rx_mib'
                    )
                    or 0
                )

            except Exception:
                rx_mib = 0.0

            try:
                tx_mib = float(
                    row.get(
                        'tx_mib'
                    )
                    or 0
                )

            except Exception:
                tx_mib = 0.0

            result.update({
                'connected': connected,

                'conn_status': (
                    'online'
                    if connected
                    else 'offline'
                ),

                'connection_status': (
                    'connected'
                    if connected
                    else 'disconnected'
                ),

                'connection_label': (
                    'Connected'
                    if connected
                    else 'Disconnected'
                ),

                'conn_reason': (
                    'handshake'
                    if connected
                    else (
                        'stale_handshake'
                        if latest_handshake > 0
                        else 'no_handshake'
                    )
                ),

                'latest_handshake': (
                    latest_handshake
                ),

                'latest_handshake_age': (
                    handshake_age
                ),

                'last_activity_at': (
                    datetime.utcfromtimestamp(
                        latest_handshake
                    ).isoformat()
                    + 'Z'
                    if latest_handshake > 0
                    else None
                ),

                'rx_bytes': int(
                    rx_mib
                    * 1024
                    * 1024
                ),

                'tx_bytes': int(
                    tx_mib
                    * 1024
                    * 1024
                ),

                'node_reported_conn_status': (
                    row.get(
                        'conn_status'
                    )
                    or row.get(
                        'connection_status'
                    )
                    or row.get(
                        'status'
                    )
                    or ''
                ),

                'node_reported_conn_reason': (
                    row.get(
                        'conn_reason'
                    )
                    or ''
                ),
            })

            return result

        interface_name = raw_iface_name

        if not interface_name:
            result[
                'runtime_available'
            ] = False

            result[
                'conn_reason'
            ] = 'interface_missing'

            return result

        cache = getattr(
            g,
            '_subscription_local_runtime_cache',
            None,
        )

        if cache is None:
            cache = {}

            g._subscription_local_runtime_cache = (
                cache
            )

        if interface_name not in cache:
            try:
                transfers, handshakes = (
                    _wg_runtime_snapshot(
                        [
                            interface_name
                        ]
                    )
                )

                cache[
                    interface_name
                ] = {
                    'ok': True,
                    'transfers': transfers,
                    'handshakes': handshakes,
                }

            except Exception as exc:
                current_app.logger.debug(
                    'Subscription runtime: local interface %s unavailable: %s',
                    interface_name,
                    exc,
                )

                cache[
                    interface_name
                ] = {
                    'ok': False,
                    'transfers': {},
                    'handshakes': {},
                }

        local_cache = (
            cache.get(
                interface_name
            )
            or {}
        )

        if not local_cache.get(
            'ok'
        ):
            result[
                'runtime_available'
            ] = False

            result[
                'conn_reason'
            ] = 'wireguard_unavailable'

            return result

        transfers = (
            local_cache.get(
                'transfers'
            )
            or {}
        )

        handshakes = (
            local_cache.get(
                'handshakes'
            )
            or {}
        )

        latest_handshake = int(
            handshakes.get(
                (
                    interface_name,
                    public_key,
                ),
                0,
            )
            or 0
        )

        handshake_age = (
            max(
                0,
                current_epoch
                - latest_handshake,
            )
            if latest_handshake > 0
            else None
        )

        connected = bool(
            latest_handshake > 0
            and handshake_age is not None
            and handshake_age
            <= handshake_window
        )

        rx_bytes, tx_bytes = (
            transfers.get(
                (
                    interface_name,
                    public_key,
                ),
                (
                    0,
                    0,
                ),
            )
        )

        result.update({
            'connected': connected,

            'conn_status': (
                'online'
                if connected
                else 'offline'
            ),

            'connection_status': (
                'connected'
                if connected
                else 'disconnected'
            ),

            'connection_label': (
                'Connected'
                if connected
                else 'Disconnected'
            ),

            'conn_reason': (
                'handshake'
                if connected
                else (
                    'stale_handshake'
                    if latest_handshake > 0
                    else 'no_handshake'
                )
            ),

            'latest_handshake': (
                latest_handshake
            ),

            'latest_handshake_age': (
                handshake_age
            ),

            'last_activity_at': (
                datetime.utcfromtimestamp(
                    latest_handshake
                ).isoformat()
                + 'Z'
                if latest_handshake > 0
                else None
            ),

            'rx_bytes': int(
                rx_bytes
                or 0
            ),

            'tx_bytes': int(
                tx_bytes
                or 0
            ),
        })

        return result

    def _subscription_row(sub, read_only=False, cached_runtime=None):

        used = int(
            (sum(int(link.peer.used_bytes_total or 0) for link in sub.links if link.peer) if read_only else _sub_used_bytes(sub))
            or 0
        )

        unlimited = bool(
            getattr(
                sub,
                'unlimited',
                False,
            )
        )

        subscription_changed = False
        linked_first_use = []

        for link in (
            getattr(
                sub,
                'links',
                [],
            )
            or []
        ):
            peer = getattr(
                link,
                'peer',
                None,
            )

            if not peer:
                continue

            peer_first_used = getattr(
                peer,
                'first_used_at',
                None,
            )

            if peer_first_used:
                linked_first_use.append(
                    peer_first_used
                )

        current_first_used = getattr(
            sub,
            'first_used_at',
            None,
        )

        if (
            not read_only
            and not current_first_used
            and linked_first_use
        ):
            sub.first_used_at = min(
                linked_first_use
            )

            current_first_used = (
                sub.first_used_at
            )

            subscription_changed = True

        if (
            not read_only
            and not current_first_used
            and used > 0
        ):
            sub.first_used_at = from_ts(
                now_ts()
            )

            current_first_used = (
                sub.first_used_at
            )

            subscription_changed = True

        if subscription_changed:
            if unlimited:
                try:
                    _clear_timer_cycle(sub)
                except Exception:
                    pass

            else:
                _apply_subscription_timer(
                    sub
                )

            _sync_all_subscription_peers(
                sub,
                rename=False,
            )

            try:
                db.session.commit()

            except Exception:
                db.session.rollback()

                current_app.logger.exception(
                    (
                        'Failed to save subscription first-use date '
                        'for subscription_id=%s'
                    ),
                    getattr(
                        sub,
                        'id',
                        '?',
                    ),
                )

        limit = _sub_limit_bytes(
            sub
        )

        remaining = (
            None
            if limit is None
            else max(
                0,
                int(limit) - used,
            )
        )

        access = subscription_access(sub, used_bytes=used)

        if not read_only and not access.get('allowed'):
            _block_subscription_runtime(
                sub,
                'subscription_' + str(access.get('reason') or 'blocked'),
            )

        locs = []

        links = sorted(
            list(
                getattr(
                    sub,
                    'links',
                    [],
                )
                or []
            ),
            key=lambda link: (
                getattr(
                    link,
                    'sort_order',
                    0,
                )
                or 0,
                getattr(
                    link,
                    'id',
                    0,
                )
                or 0,
            ),
        )

        runtime_counts = {
            'total': 0,
            'enabled': 0,
            'disabled': 0,
            'blocked': 0,
        }

        for link in links:
            peer = getattr(
                link,
                'peer',
                None,
            )

            if not peer:
                continue

            iface = getattr(
                peer,
                'iface',
                None,
            )

            raw_name = (
                getattr(
                    iface,
                    'name',
                    '',
                )
                or ''
            )

            node_id = (
                getattr(
                    iface,
                    'node_id',
                    None,
                )
                if iface
                else None
            )

            is_legacy_node_name = bool(
                raw_name.startswith('n')
                and ':' in raw_name
            )

            scope = (
                'node'
                if (
                    node_id is not None
                    or is_legacy_node_name
                )
                else 'local'
            )

            interface_name = (
                raw_name.split(
                    ':',
                    1,
                )[1]
                if is_legacy_node_name
                else raw_name
            )

            peer_status = str(
                getattr(
                    peer,
                    'status',
                    None,
                )
                or 'offline'
            ).lower()
            lifecycle_state = effective_peer_state(peer_status, access)

            runtime_counts['total'] += 1

            if peer_status == 'blocked':
                runtime_counts['blocked'] += 1

            elif peer_status == 'online':
                runtime_counts['enabled'] += 1

            else:
                runtime_counts['disabled'] += 1

            peer_first_used = getattr(
                peer,
                'first_used_at',
                None,
            )

            node = (
                getattr(
                    iface,
                    'node',
                    None,
                )
                if iface
                else None
            )
            try:
                live = ((cached_runtime or {}).get(peer.id, {'connected': False, 'conn_status': 'unknown', 'connection_status': 'unknown', 'connection_label': 'Awaiting refresh', 'runtime_available': False}) if read_only else _subscription_peer_runtime(peer))

            except Exception:
                current_app.logger.debug(
                    (
                        'Could not read subscription runtime '
                        'for peer_id=%s'
                    ),
                    getattr(
                        peer,
                        'id',
                        '?',
                    ),
                    exc_info=True,
                )

                live = {
                    'connected': False,
                    'conn_status': 'offline',
                    'connection_status': (
                        'disconnected'
                    ),
                    'connection_label': (
                        'Disconnected'
                    ),
                    'conn_reason': (
                        'runtime_error'
                    ),
                    'latest_handshake': 0,
                    'latest_handshake_age': None,
                    'last_activity_at': None,
                    'runtime_available': False,
                }

            locs.append({
                'link_id': getattr(
                    link,
                    'id',
                    None,
                ),

                'peer_id': getattr(
                    peer,
                    'id',
                    None,
                ),

                'scope': scope,
                'node_id': node_id,

                'node_name': (
                    getattr(
                        node,
                        'name',
                        '',
                    )
                    or ''
                ),

                'iface': interface_name,

                'name': (
                    getattr(
                        peer,
                        'name',
                        '',
                    )
                    or ''
                ),

                'address': (
                    getattr(
                        peer,
                        'address',
                        '',
                    )
                    or ''
                ),

                'endpoint': (
                    getattr(
                        peer,
                        'endpoint',
                        '',
                    )
                    or ''
                ),

                'allowed_ips': (
                    getattr(
                        peer,
                        'allowed_ips',
                        '',
                    )
                    or ''
                ),

                'dns': (
                    getattr(
                        peer,
                        'dns',
                        '',
                    )
                    or ''
                ),

                            'status': peer_status,

                'panel_status': (
                    peer_status
                ),
                'effective_status': lifecycle_state['status'],
                'status_reason': lifecycle_state['reason'],
                'status_reason_label': lifecycle_state['label'],

                'connected': bool(
                    live.get(
                        'connected'
                    )
                ),

                'conn_status': (
                    live.get(
                        'conn_status'
                    )
                    or 'offline'
                ),

                'connection_status': (
                    live.get(
                        'connection_status'
                    )
                    or 'disconnected'
                ),

                'connection_label': (
                    live.get(
                        'connection_label'
                    )
                    or 'Disconnected'
                ),

                'conn_reason': (
                    live.get(
                        'conn_reason'
                    )
                    or 'no_recent_activity'
                ),

                'latest_handshake': int(
                    live.get(
                        'latest_handshake'
                    )
                    or 0
                ),

                'latest_handshake_age': (
                    live.get(
                        'latest_handshake_age'
                    )
                ),

                'last_activity_at': (
                    live.get(
                        'last_activity_at'
                    )
                ),

                'runtime_available': bool(
                    live.get(
                        'runtime_available',
                        True,
                    )
                ),

                'used_bytes': int(
                    getattr(
                        peer,
                        'used_bytes_total',
                        0,
                    )
                    or 0
                ),

                'first_used_at': isoz(
                    peer_first_used
                ),

                'first_used_at_display': _panel_display_datetime(
                    peer_first_used
                ),

                'first_used_at_ts': to_ts(
                    peer_first_used
                ),

                'location_label': (
                    getattr(
                        link,
                        'location_label',
                        '',
                    )
                    or ''
                ),

                'country_code': (
                    getattr(
                        link,
                        'country_code',
                        '',
                    )
                    or ''
                ),

                'flag': (
                    getattr(
                        link,
                        'flag',
                        '',
                    )
                    or ''
                ),
            })


        connected_locations = [
            location
            for location in locs
            if bool(
                location.get(
                    'connected'
                )
            )
        ]

        runtime_locations = [
            location
            for location in locs
            if bool(
                location.get(
                    'runtime_available',
                    True,
                )
            )
        ]

        activity_locations = [
            location
            for location in locs
            if int(
                location.get(
                    'latest_handshake'
                )
                or 0
            ) > 0
        ]

        active_location = None

        if connected_locations:
            active_location = max(
                connected_locations,
                key=lambda location: int(
                    location.get(
                        'latest_handshake'
                    )
                    or 0
                ),
            )

        elif activity_locations:
            active_location = max(
                activity_locations,
                key=lambda location: int(
                    location.get(
                        'latest_handshake'
                    )
                    or 0
                ),
            )

        connection = {
            'connected': bool(
                connected_locations
            ),

            'status': (
                'connected'
                if connected_locations
                else 'disconnected'
            ),

            'label': (
                'Connected'
                if connected_locations
                else 'Disconnected'
            ),

            'connected_count': len(
                connected_locations
            ),

            'runtime_count': len(
                runtime_locations
            ),

            'total_count': len(
                locs
            ),

            'active_peer_id': (
                (
                    active_location
                    or {}
                ).get(
                    'peer_id'
                )
            ),

            'active_peer_name': (
                (
                    active_location
                    or {}
                ).get(
                    'name'
                )
                or ''
            ),

            'active_scope': (
                (
                    active_location
                    or {}
                ).get(
                    'scope'
                )
                or ''
            ),

            'active_node_id': (
                (
                    active_location
                    or {}
                ).get(
                    'node_id'
                )
            ),

            'active_node_name': (
                (
                    active_location
                    or {}
                ).get(
                    'node_name'
                )
                or ''
            ),

            'active_iface': (
                (
                    active_location
                    or {}
                ).get(
                    'iface'
                )
                or ''
            ),

            'latest_handshake': int(
                (
                    (
                        active_location
                        or {}
                    ).get(
                        'latest_handshake'
                    )
                    or 0
                )
            ),

            'last_activity_at': (
                (
                    active_location
                    or {}
                ).get(
                    'last_activity_at'
                )
            ),

            'last_activity_age': (
                (
                    active_location
                    or {}
                ).get(
                    'latest_handshake_age'
                )
            ),
        }

        first_used_at = getattr(
            sub,
            'first_used_at',
            None,
        )

        created_at = getattr(
            sub,
            'created_at',
            None,
        )

        expires_at = from_ts(_effective_expiry_ts(sub)) if not unlimited else None

        ttl_seconds = (
            None
            if unlimited
            else _sub_ttl_seconds(
                sub
            )
        )

        return {
            'id': sub.id,
            'name': sub.name,
            'token': sub.token,
            'note': sub.note or '',
            'display_timezone': _panel_timezone_name(),

            'data_limit_value': int(
                getattr(
                    sub,
                    'data_limit_value',
                    0,
                )
                or 0
            ),

            'data_limit_unit': (
                getattr(
                    sub,
                    'data_limit_unit',
                    None,
                )
                or 'Gi'
            ),

            'limit_bytes': limit,
            'used_bytes': used,
            'remaining_bytes': remaining,

            'usage_pct': (
                round(
                    (
                        used
                        / int(limit)
                    )
                    * 100,
                    2,
                )
                if limit
                else 0
            ),

            'time_limit_days': _sub_float(
                getattr(
                    sub,
                    'time_limit_days',
                    0,
                )
            ),

            'ttl_seconds': ttl_seconds,

            'start_on_first_use': bool(
                getattr(
                    sub,
                    'start_on_first_use',
                    False,
                )
            ),

            'created_at': isoz(
                created_at
            ),

            'created_at_display': _panel_display_datetime(
                created_at
            ),

            'created_at_ts': to_ts(
                created_at
            ),

            'first_used_at': isoz(
                first_used_at
            ),

            'first_used_at_display': _panel_display_datetime(
                first_used_at
            ),

            'first_used_at_ts': to_ts(
                first_used_at
            ),

            'expires_at': isoz(
                expires_at
            ),

            'expires_at_display': _panel_display_datetime(
                expires_at
            ),

            'expires_at_ts': to_ts(
                expires_at
            ),

            'unlimited': unlimited,

            'phone_number': (
                getattr(
                    sub,
                    'phone_number',
                    '',
                )
                or ''
            ),

            'telegram_id': (
                getattr(
                    sub,
                    'telegram_id',
                    '',
                )
                or ''
            ),

            'enabled': bool(
                getattr(
                    sub,
                    'enabled',
                    True,
                )
            ),
            'access': access,
            'state_reason': access.get('reason') or '',
            'state_label': access.get('label') or 'Ready',

                    'runtime_counts': runtime_counts,

            'connection': connection,

            'connected': bool(
                connection.get(
                    'connected'
                )
            ),

            'connection_status': (
                connection.get(
                    'status'
                )
                or 'disconnected'
            ),

            'connection_label': (
                connection.get(
                    'label'
                )
                or 'Disconnected'
            ),

            'public_url': _sub_public_url(
                sub
            ),

            'config_url': _sub_config_url(
                sub
            ),

            'locations': locs,
        }

    def _network_int_cidr(value):

        raw = str(value or '').split(',', 1)[0].strip()

        if not raw:
            return ''

        try:
            return str(
                ipaddress.ip_interface(
                    raw
                ).network
            )
        except Exception:
            return ''

    def _apnd_allowed_route(allowed_ips, route):
        values = [
            item.strip()
            for item in str(
                allowed_ips or ''
            ).split(',')
            if item.strip()
        ]

        route = str(route or '').strip()

        if not route:
            return ', '.join(values)

        if route not in values:
            values.append(route)

        return ', '.join(values)

    def _peer_payload_subscription(sub,target,data,idx=0,total=1,):

        name = (target.get('peer_name')or '').strip()

        if not name:
            base = (
                sub.name
                or data.get('name')
                or 'subscription'
            ).strip() or 'subscription'

            name = (
                base
                if total <= 1
                else f'{base}-{idx + 1}')

        allowed_ips = (data.get('allowed_ips')or '0.0.0.0/0, ::/0').strip()

        if bool(data.get('include_internal_network',False,)):
            interface_cidr = (target.get('server_cidr')or target.get('interface_address')or target.get('iface_address')or target.get('address')or '')
            internal_network = (_network_int_cidr(interface_cidr))
            allowed_ips = _apnd_allowed_route(allowed_ips,internal_network,)

        return {
            'name': name,
            'allowed_ips': allowed_ips,
            'endpoint': parse_endpoint_string(data.get('endpoint')),
            'peer_endpoint': (data.get('peer_endpoint')or '').strip(),
            'persistent_keepalive':data.get('persistent_keepalive') or None,
            'mtu':data.get('mtu') or None,
            'dns':data.get('dns') or None,
            'data_limit_value': int(getattr(sub,'data_limit_value',0,) or 0),
            'data_limit_unit': (getattr(sub,'data_limit_unit',None,)or 'Gi'),
            'time_limit_days': (_sub_float(getattr(sub,'time_limit_days',0,))or None),
            'start_on_first_use': bool(getattr(sub,'start_on_first_use',False,)),
            'unlimited': bool(getattr(sub,'unlimited',False,)),
            'phone_number': (getattr(sub,'phone_number','',)or ''),
            'telegram_id': (getattr(sub,'telegram_id','',)or ''),}

    def _stage_reseller_peer(target, payload, compensation):
        return _create_subscription_peer(target, payload, compensation=compensation, stage=True)

    def _create_subscription_peer(target, payload, compensation=None, *, stage=False):
        scope = (target.get('scope') or 'local').lower()
        priv = subprocess.check_output(['wg', 'genkey'], timeout=3).strip().decode()
        pub = subprocess.check_output(['wg', 'pubkey'], input=priv.encode(), timeout=3).strip().decode()
        payload = dict(payload)
        peer_endpoint = (payload.pop('peer_endpoint', '') or '').strip()
        created_ts = now_ts()

        if scope == 'node':
            nid = _sub_int(target.get('node_id'))
            iface_name = (target.get('iface') or '').strip()
            if not nid or not iface_name:
                raise ValueError('node_id and iface are required for node target')

            node = db.session.get(Node, nid) or abort(404)

            if stage:
                iface = db.session.get(InterfaceConfig, target['iface_id'])
                if not iface or iface.node_id != nid or iface.name.split(':',1)[-1] != iface_name:
                    raise ValueError('The assigned node interface changed.')
            else:
                iface = ensure_node_mirror_iface(
                    node, iface_name,
                    {
                        'listen_port': _sub_int(target.get('listen_port'), 51820),
                        'address': target.get('server_cidr') or target.get('interface_address'),
                        'mtu': payload.get('mtu'),
                        'dns': payload.get('dns'),
                        'public_key': target.get('public_key'),
                    },
                    listen_port=_sub_int(target.get('listen_port'), 51820),
                    server_cidr=target.get('server_cidr') or target.get('interface_address'),
                    mtu=payload.get('mtu'),
                    dns=payload.get('dns'),
                )

            if compensation is not None:
                compensation.register_node(node, pub)

            addr = node_install_peer(
                node, iface_name, iface,
                public_key=pub,
                requested_address=requested_peer_address_from_target(iface, target),
                peer_endpoint=peer_endpoint,
                keepalive=payload.get('persistent_keepalive') or 0,
                mtu=payload.get('mtu'),
                dns=payload.get('dns'),
                allowed_ips=payload.get('allowed_ips') or '0.0.0.0/0, ::/0',
            )
            peer = Peer(
                iface_id=iface.id,

                public_key=pub,
                private_key=priv,

                created_at=from_ts(created_ts),
                timer_started_at=from_ts(created_ts),

                address=addr,

                peer_endpoint=(peer_endpoint or None),

                status='online',

                **payload,
            )
            if not stage:
                db.session.add(peer)
                db.session.flush()
            return peer

        iface_id = _sub_int(target.get('iface_id'))
        iface = db.session.get(InterfaceConfig, iface_id) if iface_id else None
        if not iface and target.get('iface'):
            iface = InterfaceConfig.query.filter_by(name=(target.get('iface') or '').strip()).first()
        if not iface:
            raise ValueError('iface_id is required for local target')

        with interface_allocation_lock(iface):
            requested = requested_peer_address_from_target(iface, target)
            addr = (allocate_peer_address(iface, requested=requested, extra_reserved=target.get('staged_addresses', ()))
                    if stage else allocate_peer_address(iface, requested=requested))

            peer = Peer(
                iface_id=iface.id,

                public_key=pub,
                private_key=priv,

                created_at=from_ts(created_ts),
                timer_started_at=from_ts(created_ts),

                address=addr,

                peer_endpoint=(peer_endpoint or None),

                status='online',

                **payload,
            )
            if stage:
                from sqlalchemy.orm.attributes import set_committed_value
                set_committed_value(peer, 'iface', iface)
            else:
                db.session.add(peer)
                db.session.flush()
            if compensation is not None:
                compensation.register_local(peer)
            install_local_peer(peer)

        return peer

    def _attach_subscription_target(sub, target, data, idx=0, total=1, compensation=None):
        if target.get('peer_id'):
            peer = db.session.get(Peer, int(target.get('peer_id'))) or abort(404)
            existing = SubscriptionPeer.query.filter_by(peer_id=peer.id).first()
            if existing and existing.subscription_id != sub.id:
                raise ValueError(f'Peer {peer.name} is already attached to another subscription')
            if existing:
                link = existing
            else:
                link = SubscriptionPeer(subscription_id=sub.id, peer_id=peer.id, owned=False)
                db.session.add(link)
                db.session.flush()
        else:
            payload = _peer_payload_subscription(sub, target, data, idx=idx, total=total)
            peer = _create_subscription_peer(target, payload, compensation=compensation)
            link = SubscriptionPeer(subscription_id=sub.id, peer_id=peer.id, owned=True)
            db.session.add(link)
            db.session.flush()
        link.sort_order = idx
        link.location_label = (target.get('location_label') or target.get('label') or target.get('location') or '').strip()
        link.country_code = (target.get('country_code') or '').strip()[:2].upper()
        link.flag = (target.get('flag') or '').strip()[:8]
        _sync_peer_subscription(link.peer, sub, idx=idx, rename=True)
        return link

    def _update_subscription_payload(sub, data, reset_timer=False):
        old_name = sub.name
        if 'name' in data:
            sub.name = (data.get('name') or sub.name or 'Subscription').strip()
        if 'note' in data:
            sub.note = (data.get('note') or '').strip()
        if 'data_limit_value' in data:
            sub.data_limit_value = _sub_int(data.get('data_limit_value'), 0)
        if 'data_limit_unit' in data:
            sub.data_limit_unit = (data.get('data_limit_unit') or 'Gi')
        if 'time_limit_days' in data:
            sub.time_limit_days = _sub_float(data.get('time_limit_days'), 0)
        if 'start_on_first_use' in data:
            sub.start_on_first_use = _sub_bool(data.get('start_on_first_use'))
        if 'unlimited' in data:
            sub.unlimited = _sub_bool(data.get('unlimited'))
        if 'phone_number' in data:
            sub.phone_number = (data.get('phone_number') or '').strip()
        if 'telegram_id' in data:
            sub.telegram_id = (data.get('telegram_id') or '').strip()
        if 'enabled' in data:
            sub.enabled = _sub_bool(data.get('enabled'))
        timer_policy_changed = any(
            k in data for k in ('time_limit_days', 'start_on_first_use', 'unlimited')
        )
        if reset_timer or timer_policy_changed:
            if reset_timer or not getattr(sub, 'start_on_first_use', False):
                sub.first_used_at = None
            _apply_subscription_timer(sub, restart=True)
        else:
            _apply_subscription_timer(sub)
        _sync_all_subscription_peers(sub, rename=True)

    def _reset_subscription_data(sub):

        result = {
            'reset_peers': 0,
            'reactivated': 0,
            'still_blocked': 0,
            'enable_failed': 0,
            'errors': [],
        }

        timer_expired = _subscription_time_expired(sub)

        for link in list(getattr(sub, 'links', []) or []):
            peer = getattr(link, 'peer', None)

            if not peer:
                continue

            result['reset_peers'] += 1

            try:
                if getattr(peer.iface, 'node_id', None) is not None:
                    node = peer.iface.node

                    response = node_post(
                        node,
                        f'/api/peer/{peer.public_key}/reset_data',
                        {},
                        timeout=12,
                    ) or {}

                    if not isinstance(response, dict):
                        raise RuntimeError(
                            'Node returned an invalid reset-data response'
                        )

                    if response.get('ok') is False:
                        raise RuntimeError(
                            response.get('detail')
                            or response.get('error')
                            or 'Node reset-data request failed'
                        )

                    current_total = response.get('total_bytes')

                    if current_total is None:
                        rx_bytes = int(response.get('rx_bytes') or 0)
                        tx_bytes = int(response.get('tx_bytes') or 0)
                        current_total = rx_bytes + tx_bytes

                    peer.bytes_offset = max(0, int(current_total or 0))

                else:
                    peer.bytes_offset = max(
                        0,
                        int(_wg_transfer(peer) or 0),
                    )

                peer.used_bytes_total = 0

            except Exception as exc:
                current_app.logger.exception(
                    'Subscription data reset failed for peer %s',
                    getattr(peer, 'id', '?'),
                )

                result['errors'].append({
                    'peer_id': getattr(peer, 'id', None),
                    'peer_name': getattr(peer, 'name', '') or '',
                    'detail': str(exc),
                })

                continue

            if peer.status == 'blocked':
                if timer_expired:
                    result['still_blocked'] += 1
                elif _enable_subscription(peer):
                    result['reactivated'] += 1
                else:
                    result['enable_failed'] += 1

            try:
                log_event(
                    peer,
                    'subscription_reset_data',
                    (
                        'Shared subscription data reset; '
                        f'new offset={int(peer.bytes_offset or 0)}'
                    ),
                )
            except Exception:
                pass

        return result

    def _reset_subscription_timer(sub):

        result = {
            'reset_peers': 0,
            'reactivated': 0,
            'still_blocked': 0,
            'enable_failed': 0,
            'errors': [],
        }

        sub.first_used_at = None
        _apply_subscription_timer(sub, restart=True)

        data_exhausted = _subscription_data_exhausted(sub)

        for link in list(getattr(sub, 'links', []) or []):
            peer = getattr(link, 'peer', None)

            if not peer:
                continue

            result['reset_peers'] += 1

            try:
                _sync_peer_subscription(
                    peer,
                    sub,
                    rename=False,
                )
            except Exception as exc:
                current_app.logger.exception(
                    'Subscription timer sync failed for peer %s',
                    getattr(peer, 'id', '?'),
                )

                result['errors'].append({
                    'peer_id': getattr(peer, 'id', None),
                    'peer_name': getattr(peer, 'name', '') or '',
                    'detail': str(exc),
                })

            if peer.status == 'blocked':
                if data_exhausted:
                    result['still_blocked'] += 1
                elif _enable_subscription(peer):
                    result['reactivated'] += 1
                else:
                    result['enable_failed'] += 1

            try:
                log_event(
                    peer,
                    'subscription_reset_timer',
                    'Shared subscription timer reset',
                )
            except Exception:
                pass

        return result

    def _subscription_data_exhausted(sub):
        limit = _sub_limit_bytes(sub)

        return bool(
            limit
            and _sub_used_bytes(sub) >= limit
        )

    def _subscription_time_expired(sub):
        ttl = _sub_ttl_seconds(sub)

        return bool(
            ttl is not None
            and ttl <= 0
        )

    def _enable_subscription(peer):

        try:
            iface = getattr(
                peer,
                'iface',
                None,
            )

            if not iface:
                raise RuntimeError(
                    'Peer interface is missing.'
                )

            if getattr(
                iface,
                'node_id',
                None,
            ) is not None:
                node = getattr(
                    iface,
                    'node',
                    None,
                )

                if not node:
                    raise RuntimeError(
                        'Peer node is missing.'
                    )

                response = node_post(
                    node,
                    (
                        f'/api/peer/'
                        f'{peer.public_key}/enable'
                    ),
                    {
                        'host_cidr': _host_peer(peer),
                    },
                    timeout=15,
                ) or {}

                if not isinstance(
                    response,
                    dict,
                ):
                    raise RuntimeError(
                        'Node returned an invalid enable response.'
                    )

                if response.get('ok') is False:
                    raise RuntimeError(
                        response.get('detail')
                        or response.get('error')
                        or 'Node peer enable failed.'
                    )

            else:
                dev = iface_devname(iface)

                if not _iface_up(dev):
                    _check_iface_up(iface)

                if not _iface_up(dev):
                    raise RuntimeError(
                        f"WireGuard interface '{dev}' is not running."
                    )

                _wg_enable(peer)
                _sync_peer(peer)

            peer.status = 'online'

            return True

        except Exception:
            current_app.logger.exception(
                'Failed enabling subscription peer %s',
                getattr(peer, 'id', '?'),
            )

            return False

    def _disable_subscription(peer):

        try:
            iface = getattr(
                peer,
                'iface',
                None,
            )

            if not iface:
                raise RuntimeError(
                    'Peer interface is missing.'
                )

            if getattr(
                iface,
                'node_id',
                None,
            ) is not None:
                node = getattr(
                    iface,
                    'node',
                    None,
                )

                if not node:
                    raise RuntimeError(
                        'Peer node is missing.'
                    )

                response = node_post(
                    node,
                    (
                        f'/api/peer/'
                        f'{peer.public_key}/disable'
                    ),
                    {
                        'host_cidr': _host_peer(peer),
                    },
                    timeout=15,
                ) or {}

                if not isinstance(
                    response,
                    dict,
                ):
                    raise RuntimeError(
                        'Node returned an invalid disable response.'
                    )

                if response.get('ok') is False:
                    raise RuntimeError(
                        response.get('detail')
                        or response.get('error')
                        or 'Node peer disable failed.'
                    )

            else:
                _wg_disable(peer)

            peer.status = 'offline'

            return True

        except Exception:
            current_app.logger.exception(
                'Failed disabling subscription peer %s',
                getattr(peer, 'id', '?'),
            )

            return False

    def _subscription_enabled(sub,enabled: bool,):
        result = {
            'total': 0,
            'changed': 0,
            'failed': 0,
            'failed_peer_ids': [],
            'errors': [],
        }

        enabled = bool(enabled)

        for link in list(
            getattr(sub, 'links', []) or []
        ):
            peer = getattr(
                link,
                'peer',
                None,
            )

            if not peer:
                continue

            result['total'] += 1

            if enabled:
                success = (
                    _enable_subscription(
                        peer
                    )
                )
            else:
                success = (
                    _disable_subscription(
                        peer
                    )
                )

            if success:
                result['changed'] += 1

                try:
                    log_event(
                        peer,
                        (
                            'subscription_enabled'
                            if enabled
                            else 'subscription_disabled'
                        ),
                        (
                            'Subscription enabled'
                            if enabled
                            else 'Subscription disabled'
                        ),
                    )
                except Exception:
                    pass

            else:
                result['failed'] += 1
                result['failed_peer_ids'].append(
                    getattr(peer, 'id', None)
                )

                result['errors'].append({
                    'peer_id': getattr(
                        peer,
                        'id',
                        None,
                    ),
                    'peer_name': (
                        getattr(peer, 'name', '')
                        or ''
                    ),
                })

        return result

    def _render_subscription_template_preview(sub, raw_settings, base_settings):
        cfg = (
            _normalize_subscription_settings(
                raw_settings,
                base=base_settings,
            )
        )

        if sub is not None:
            preview_sub = sub

            try:
                preview_data = (
                    _subscription_public_payload(
                        sub
                    )
                )
            except Exception:
                preview_data = {}

        else:
            from types import SimpleNamespace

            preview_sub = SimpleNamespace(
                id=0,
                name='premium-user',
                token='preview',
            )

            gib = 1024 ** 3

            preview_data = {
                'id': 0,
                'name': 'premium-user',
                'token': 'preview',

                'enabled': True,
                'unlimited': False,

                'limit_bytes': 10 * gib,
                'used_bytes': int(
                    2.4 * gib
                ),

                'data_limit_value': 10,
                'data_limit_unit': 'Gi',

                'start_on_first_use': False,

                'first_used_at': (
                    '2026-08-07T09:30:00Z'
                ),

                'expires_at': (
                    '2026-08-31T18:00:00Z'
                ),

                'expires_at_ts': None,

                'ttl_seconds': (
                    12 * 86400
                    + 4 * 3600
                ),

                'access': {
                    'allowed': True,
                    'reason': '',
                    'message': '',
                    'has_inbounds': True,
                },

                'locations': [
                    {
                        'link_id': 1,
                        'peer_id': 1,
                        'name': 'Amsterdam',
                        'status': 'online',
                        'endpoint': '',
                        'public_host': '',
                        'location_label': (
                            'Netherlands'
                        ),
                        'country_code': 'NL',
                        'flag': '🇳🇱',
                    },
                    {
                        'link_id': 2,
                        'peer_id': 2,
                        'name': 'Frankfurt',
                        'status': 'online',
                        'endpoint': '',
                        'public_host': '',
                        'location_label': (
                            'Germany'
                        ),
                        'country_code': 'DE',
                        'flag': '🇩🇪',
                    },
                    {
                        'link_id': 3,
                        'peer_id': 3,
                        'name': 'Backup',
                        'status': 'offline',
                        'endpoint': '',
                        'public_host': '',
                        'location_label': (
                            'Netherlands'
                        ),
                        'country_code': 'NL',
                        'flag': '🇳🇱',
                    },
                ],
            }

        support = (
            cfg.get('support')
            or {}
        )

        portal_title = (
            cfg.get('portal_title')
            or preview_sub.name
        )

        return render_template(
            'subscription_public.html',

            preview_mode=True,

            sub=preview_sub,
            data=preview_data,

            portal_settings=cfg,

            sub_layout=cfg.get(
                'layout',
                'aurora',
            ),

            sub_display_mode=cfg.get(
                'display_mode',
                'hybrid',
            ),

            sub_animation=cfg.get(
                'animation',
                'balanced',
            ),

            sub_background=cfg.get(
                'background',
                'aurora',
            ),

            portal_label=cfg.get(
                'portal_label',
                'Secure WireGuard portal',
            ),

            portal_icon=cfg.get(
                'portal_icon',
                'fas fa-bolt',
            ),

            portal_title=portal_title,

            portal_subtitle=cfg.get(
                'portal_subtitle',
                (
                    'Your account is ready. '
                    'Install WireGuard, then '
                    'scan QR or import a config.'
                ),
            ),

            support_portal_label=cfg.get(
                'portal_label',
                'Secure WireGuard portal',
            ),

            support_portal_icon=cfg.get(
                'portal_icon',
                'fas fa-bolt',
            ),

            support_portal_title=(
                portal_title
            ),

            support_portal_subtitle=cfg.get(
                'portal_subtitle',
                (
                    'Your account is ready. '
                    'Install WireGuard, then '
                    'scan QR or import a config.'
                ),
            ),

            support_telegram=support.get(
                'telegram',
                '',
            ),

            support_whatsapp=support.get(
                'whatsapp',
                '',
            ),

            support_instagram=support.get(
                'instagram',
                '',
            ),

            support_phone=support.get(
                'phone',
                '',
            ),

            support_website=support.get(
                'website',
                '',
            ),

            support_email=support.get(
                'email',
                '',
            ),
        )

    return {
        '_load_subscription_settings': _load_subscription_settings,
        '_save_subscription_settings': _save_subscription_settings,
        '_load_subscription_portal_overrides': _load_subscription_portal_overrides,
        '_save_subscription_portal_overrides': _save_subscription_portal_overrides,
        '_subscription_portal_override': _subscription_portal_override,
        '_sub_used_bytes': _sub_used_bytes,
        '_sub_public_url': _sub_public_url,
        '_sub_config_url': _sub_config_url,
        '_apply_subscription_timer': _apply_subscription_timer,
        '_sync_peer_subscription': _sync_peer_subscription,
        '_sync_all_subscription_peers': _sync_all_subscription_peers,
        '_block_subscription_runtime': _block_subscription_runtime,
        '_subscription_peer_runtime': _subscription_peer_runtime,
        '_subscription_row': _subscription_row,
        '_network_int_cidr': _network_int_cidr,
        '_apnd_allowed_route': _apnd_allowed_route,
        '_peer_payload_subscription': _peer_payload_subscription,
        '_stage_reseller_peer': _stage_reseller_peer,
        '_create_subscription_peer': _create_subscription_peer,
        '_attach_subscription_target': _attach_subscription_target,
        '_update_subscription_payload': _update_subscription_payload,
        '_reset_subscription_data': _reset_subscription_data,
        '_reset_subscription_timer': _reset_subscription_timer,
        '_subscription_data_exhausted': _subscription_data_exhausted,
        '_subscription_time_expired': _subscription_time_expired,
        '_enable_subscription': _enable_subscription,
        '_disable_subscription': _disable_subscription,
        '_subscription_enabled': _subscription_enabled,
        '_render_subscription_template_preview': _render_subscription_template_preview,
    }
