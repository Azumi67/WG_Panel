(() => {
  const root = document.documentElement;
  let design = 'modern';
  let theme = 'auto';
  let motion = 'dynamic';

  try {
    const choice = localStorage.getItem('wg-auth-design') || 'follow';
    design = choice === 'follow' ? (localStorage.getItem('wg-design') || 'modern') : choice;
    theme = localStorage.getItem('wg-theme') || 'auto';
    const storedMotion = localStorage.getItem('wg-workspace-motion') || 'dynamic';
    motion = storedMotion === 'auto' ? 'dynamic' : storedMotion;
    if (!['dynamic', 'calm', 'off'].includes(motion)) motion = 'dynamic';
  } catch (_) {}

  root.dataset.design = design === 'legacy' ? 'legacy' : 'modern';
  root.dataset.workspaceMotion = motion;

  const scheme = matchMedia('(prefers-color-scheme: dark)');
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const applyTheme = () => {
    root.dataset.theme = theme === 'auto' ? (scheme.matches ? 'dark' : 'light') : theme;
  };
  applyTheme();
  root.dataset.authPaused = String(document.hidden);
  scheme.addEventListener?.('change', applyTheme);

  document.addEventListener('visibilitychange', () => {
    root.dataset.authPaused = String(document.hidden);
  });

  const SVG_NS = 'http://www.w3.org/2000/svg';
  const svgEl = (name, attrs = {}) => {
    const el = document.createElementNS(SVG_NS, name);
    for (const [key, value] of Object.entries(attrs)) el.setAttribute(key, String(value));
    return el;
  };

  const nodes = [
    [70,130,1],[175,92,0],[292,165,1],[405,93,0],[518,142,1],[650,86,0],[782,148,1],[914,92,0],[1050,144,1],[1190,83,0],[1320,158,1],[1518,105,0],
    [105,316,0],[230,270,1],[350,338,0],[492,273,1],[628,326,0],[770,255,1],[930,320,0],[1072,270,1],[1220,338,0],[1362,265,1],[1510,332,0],
    [58,520,1],[190,467,0],[326,542,1],[455,475,0],[590,535,1],[720,460,0],[875,535,1],[1012,466,0],[1156,548,1],[1290,462,0],[1430,532,1],[1548,470,0],
    [95,730,0],[245,660,1],[386,735,0],[526,654,1],[670,742,0],[810,665,1],[956,738,0],[1100,650,1],[1240,735,0],[1394,664,1],[1532,746,0]
  ];

  const links = [
    [0,2],[1,3],[2,4],[3,5],[4,6],[5,7],[6,8],[7,9],[8,10],[9,11],
    [0,12],[2,14],[4,16],[6,18],[8,20],[10,22],[11,22],
    [12,13],[13,14],[14,15],[15,16],[16,17],[17,18],[18,19],[19,20],[20,21],[21,22],
    [12,24],[13,25],[14,26],[15,27],[16,28],[17,29],[18,30],[19,31],[20,32],[21,33],[22,34],
    [23,24],[24,25],[25,26],[26,27],[27,28],[28,29],[29,30],[30,31],[31,32],[32,33],[33,34],
    [23,35],[25,37],[27,39],[29,41],[31,43],[33,44],[34,44],
    [35,36],[36,37],[37,38],[38,39],[39,40],[40,41],[41,42],[42,43],[43,44],
    [2,13],[4,15],[6,17],[8,19],[10,21],[13,24],[15,26],[17,28],[19,30],[21,32],[24,36],[26,38],[28,40],[30,42],[32,44]
  ];

  const hubNodes = new Set([2, 17, 30, 41]);

  function curvedPath(a, b, bend = 0) {
    const [x1, y1] = nodes[a];
    const [x2, y2] = nodes[b];
    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2;
    const dx = x2 - x1;
    const dy = y2 - y1;
    const len = Math.max(1, Math.hypot(dx, dy));
    const nx = -dy / len;
    const ny = dx / len;
    const curve = bend || (((a * 17 + b * 13) % 17) - 8) * 1.45;
    return `M${x1} ${y1} Q${(mx + nx * curve).toFixed(1)} ${(my + ny * curve).toFixed(1)} ${x2} ${y2}`;
  }

  function buildConstellation(scene) {
    const svg = svgEl('svg', {
      class: 'auth-constellation',
      viewBox: '0 0 1600 900',
      preserveAspectRatio: 'xMidYMid slice',
      'aria-hidden': 'true'
    });

    const defs = svgEl('defs');
    const glow = svgEl('filter', { id: 'auth-node-glow', x: '-100%', y: '-100%', width: '300%', height: '300%' });
    glow.append(svgEl('feGaussianBlur', { stdDeviation: '5', result: 'blur' }));
    const merge = svgEl('feMerge');
    merge.append(svgEl('feMergeNode', { in: 'blur' }), svgEl('feMergeNode', { in: 'SourceGraphic' }));
    glow.append(merge);
    defs.append(glow);

    const coreGrad = svgEl('radialGradient', { id: 'auth-core-gradient', cx: '50%', cy: '50%', r: '50%' });
    coreGrad.append(
      svgEl('stop', { offset: '0%', 'stop-color': 'var(--auth-core-hot)', 'stop-opacity': '.32' }),
      svgEl('stop', { offset: '48%', 'stop-color': 'var(--auth-core-mid)', 'stop-opacity': '.12' }),
      svgEl('stop', { offset: '100%', 'stop-color': 'var(--auth-core-mid)', 'stop-opacity': '0' })
    );
    defs.append(coreGrad);
    svg.append(defs);

    const far = svgEl('g', { class: 'constellation-layer constellation-far' });
    const mid = svgEl('g', { class: 'constellation-layer constellation-mid' });
    const near = svgEl('g', { class: 'constellation-layer constellation-near' });
    const edgeGroup = svgEl('g', { class: 'constellation-edges' });
    const registerEdges = svgEl('g', { class: 'constellation-register-edges' });
    const routeGroup = svgEl('g', { class: 'constellation-routes' });
    const liveGroup = svgEl('g', { class: 'constellation-live-routes' });
    const nodeGroup = svgEl('g', { class: 'constellation-nodes' });

    links.forEach((pair, i) => {
      const [from, to] = pair;
      const p = svgEl('path', {
        d: curvedPath(from, to),
        class: `constellation-edge edge-${i % 5}`,
        'data-link': i,
        'data-from': from,
        'data-to': to
      });
      (i % 7 === 0 ? registerEdges : edgeGroup).append(p);
      if (i % 16 === 2 || i % 19 === 5) {
        routeGroup.append(svgEl('path', {
          d: curvedPath(from, to),
          class: `constellation-route route-${i % 4}`,
          'pathLength': '1',
          'data-from': from,
          'data-to': to
        }));
      }
    });

    nodes.forEach(([x, y, hot], i) => {
      const g = svgEl('g', {
        class: `constellation-node-wrap depth-${i % 3}${hubNodes.has(i) ? ' is-hub' : ''}`,
        'data-node': i
      });
      if (hubNodes.has(i)) {
        g.append(
          svgEl('circle', { cx: x, cy: y, r: hot ? 20 : 17, class: 'constellation-hub-ring hub-ring-outer' }),
          svgEl('circle', { cx: x, cy: y, r: hot ? 13 : 11, class: 'constellation-hub-ring hub-ring-inner' })
        );
      }
      const halo = svgEl('circle', { cx: x, cy: y, r: hot ? 13 : 9, class: 'constellation-node-halo' });
      const dot = svgEl('circle', { cx: x, cy: y, r: hot ? 3.4 : 2.1, class: hot ? 'constellation-node hot' : 'constellation-node' });
      g.append(halo, dot);
      nodeGroup.append(g);
    });

    const core = svgEl('g', { class: 'constellation-core', transform: 'translate(800 450)' });
    core.append(
      svgEl('circle', { cx: 0, cy: 0, r: 172, fill: 'url(#auth-core-gradient)', class: 'core-ambient' }),
      svgEl('circle', { cx: 0, cy: 0, r: 128, class: 'core-ring ring-a' }),
      svgEl('circle', { cx: 0, cy: 0, r: 102, class: 'core-ring ring-b' }),
      svgEl('path', { d: 'M0 -92 L79 -46 L79 46 L0 92 L-79 46 L-79 -46 Z', class: 'core-hex hex-a' }),
      svgEl('path', { d: 'M0 -66 L57 -33 L57 33 L0 66 L-57 33 L-57 -33 Z', class: 'core-hex hex-b' }),
      svgEl('circle', { cx: 0, cy: 0, r: 8, class: 'core-dot' })
    );

    far.append(edgeGroup);
    mid.append(registerEdges);
    near.append(routeGroup, liveGroup, nodeGroup, core);
    svg.append(far, mid, near);
    scene.append(svg);
    return { svg, edgeGroup, registerEdges, routeGroup, liveGroup, nodeGroup, core };
  }

  const mobileNodes = [
    [34,96],[386,112],[62,226],[354,258],[42,402],[378,430],
    [76,570],[344,602],[48,752],[374,782],[210,150]
  ];
  const mobileLinks = [
    [0,10],[10,1],[0,2],[1,3],[2,3],[2,4],[3,5],
    [4,5],[4,6],[5,7],[6,7],[6,8],[7,9]
  ];

  function curvedMobilePath(a, b, bend = 0) {
    const [x1, y1] = mobileNodes[a];
    const [x2, y2] = mobileNodes[b];
    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2;
    const dx = x2 - x1;
    const dy = y2 - y1;
    const len = Math.max(1, Math.hypot(dx, dy));
    const nx = -dy / len;
    const ny = dx / len;
    const curve = bend || (((a * 11 + b * 7) % 11) - 5) * 2.0;
    return `M${x1} ${y1} Q${(mx + nx * curve).toFixed(1)} ${(my + ny * curve).toFixed(1)} ${x2} ${y2}`;
  }

  function buildMobileGateway(scene) {
    const svg = svgEl('svg', {
      class: 'auth-mobile-gateway',
      viewBox: '0 0 420 900',
      preserveAspectRatio: 'xMidYMid slice',
      'aria-hidden': 'true'
    });
    const edges = svgEl('g', { class: 'mobile-gateway-edges' });
    const live = svgEl('g', { class: 'mobile-gateway-live' });
    const nodeGroup = svgEl('g', { class: 'mobile-gateway-nodes' });

    mobileLinks.forEach(([from,to], i) => {
      edges.append(svgEl('path', {
        d: curvedMobilePath(from,to),
        class: `mobile-gateway-edge mobile-edge-${i % 4}`,
        'data-mobile-link': i,
        'data-from': from,
        'data-to': to
      }));
    });

    mobileNodes.forEach(([x,y], i) => {
      const g = svgEl('g', {
        class: `mobile-gateway-node-wrap${i === 10 ? ' is-gateway' : ''}`,
        'data-mobile-node': i
      });
      if (i === 10) {
        g.append(svgEl('path', {
          d: `M${x} ${y-14} L${x+14} ${y} L${x} ${y+14} L${x-14} ${y} Z`,
          class: 'mobile-gateway-core-ring'
        }));
      }
      g.append(
        svgEl('circle', { cx:x, cy:y, r:i === 10 ? 12 : 8, class:'mobile-gateway-node-halo' }),
        svgEl('circle', { cx:x, cy:y, r:i === 10 ? 3.8 : 2.5, class:'mobile-gateway-node' })
      );
      nodeGroup.append(g);
    });

    svg.append(edges, live, nodeGroup);
    scene.append(svg);
    return { svg, edges, live, nodeGroup };
  }

  function setupModernAuth() {
    if (root.dataset.design !== 'modern') return;

    const isRegister = /register/i.test(location.pathname) || /register/i.test(document.title);
    root.dataset.authPage = isRegister ? 'register' : 'login';

    const scene = document.createElement('div');
    scene.className = 'auth-live-scene auth-constellation-scene';
    scene.dataset.page = isRegister ? 'register' : 'login';
    scene.setAttribute('aria-hidden', 'true');
    scene.innerHTML = `
      <div class="auth-atmosphere auth-atmosphere-a"></div>
      <div class="auth-atmosphere auth-atmosphere-b"></div>
      <div class="auth-depth-stars auth-depth-stars-far"></div>
      <div class="auth-depth-stars auth-depth-stars-near"></div>
      <div class="auth-gateway-ripple"></div>`;
    const constellation = buildConstellation(scene);
    const mobileGateway = buildMobileGateway(scene);
    document.body.prepend(scene);

    const controls = document.createElement('div');
    controls.className = 'auth-appearance-controls';
    controls.innerHTML = `
      <div role="group" aria-label="Color theme">
        <button type="button" data-auth-theme="light" aria-label="Light theme" title="Light theme">☀</button>
        <button type="button" data-auth-theme="dark" aria-label="Dark theme" title="Dark theme">☾</button>
        <button type="button" data-auth-theme="auto" aria-label="Use device theme" title="Use device theme">Auto</button>
      </div>
      <button type="button" data-auth-motion aria-label="Animation mode"></button>`;

    const header = document.createElement('header');
    header.className = 'auth-page-header';
    const card = document.querySelector('.auth-card');
    const brand = card?.querySelector('.brand,.brand-badge');
    if (brand) header.append(brand);
    header.append(controls);
    card?.prepend(header);

    const readTheme = () => {
      try { theme = localStorage.getItem('wg-theme') || 'auto'; } catch (_) { theme = 'auto'; }
    };

    const paint = () => {
      root.dataset.theme = theme === 'auto' ? (scheme.matches ? 'dark' : 'light') : theme;
      controls.querySelectorAll('[data-auth-theme]').forEach(btn => {
        btn.setAttribute('aria-pressed', String(btn.dataset.authTheme === theme));
      });
      const mode = root.dataset.workspaceMotion || 'dynamic';
      const motionBtn = controls.querySelector('[data-auth-motion]');
      const labels = {
        dynamic: ['✦ Dynamic', 'Dynamic background animation. Click for Calm mode.'],
        calm: ['≈ Calm', 'Calm background animation. Click to turn motion off.'],
        off: ['○ Off', 'Background animation is off. Click for Dynamic mode.']
      };
      const [text, label] = labels[mode] || labels.dynamic;
      motionBtn.textContent = text;
      motionBtn.title = label;
      motionBtn.setAttribute('aria-label', label);
      motionBtn.setAttribute('aria-pressed', String(mode !== 'off'));
    };

    controls.addEventListener('click', event => {
      const button = event.target.closest('button');
      if (!button) return;
      if (button.dataset.authTheme) {
        theme = button.dataset.authTheme;
        try { localStorage.setItem('wg-theme', theme); } catch (_) {}
      } else if (button.hasAttribute('data-auth-motion')) {
        const mode = root.dataset.workspaceMotion || 'dynamic';
        root.dataset.workspaceMotion = mode === 'dynamic' ? 'calm' : (mode === 'calm' ? 'off' : 'dynamic');
        try { localStorage.setItem('wg-workspace-motion', root.dataset.workspaceMotion); } catch (_) {}
      }
      paint();
      resetLiveMotion?.();
    });

    const classifyInput = input => {
      const key = `${input.id || ''} ${input.name || ''}`.toLowerCase();
      if (key.includes('twofa') || key.includes('totp') || key.includes('code')) return 'verify';
      if (key.includes('pass')) return 'secure';
      if (key.includes('user') || key.includes('name')) return 'identity';
      return 'profile';
    };

    card?.querySelectorAll('input:not([type="hidden"]), select, textarea').forEach(input => {
      input.addEventListener('focus', () => {
        scene.dataset.focus = classifyInput(input);
        root.dataset.authFocus = scene.dataset.focus;
      });
      input.addEventListener('blur', () => {
        if (!card.contains(document.activeElement)) {
          delete scene.dataset.focus;
          delete root.dataset.authFocus;
        }
      });
    });

    card?.querySelectorAll('input[type=password]').forEach(input => {
      const holder = input.closest('.form-group') || input.closest('label') || input.parentElement;
      if (!holder || holder.querySelector('.auth-caps-hint')) return;
      const hint = document.createElement('p');
      hint.className = 'auth-caps-hint';
      hint.hidden = true;
      hint.textContent = 'Caps Lock is on';
      hint.setAttribute('role', 'status');
      holder.append(hint);
      const check = event => { hint.hidden = !event.getModifierState?.('CapsLock'); };
      input.addEventListener('keydown', check);
      input.addEventListener('keyup', check);
      input.addEventListener('blur', () => { hint.hidden = true; });
    });

    const mainForm = isRegister
      ? card?.querySelector('form[action*="register"]') || card?.querySelector('form')
      : card?.querySelector('#login-form') || card?.querySelector('form');

    const updateRegisterProgress = () => {
      if (!isRegister || !mainForm) return;
      const fields = [...mainForm.querySelectorAll('input:not([type="hidden"]):not([type="checkbox"]):not([type="submit"])')]
        .filter(el => !el.disabled && el.offsetParent !== null);
      if (!fields.length) return;
      const filled = fields.filter(el => String(el.value || '').trim().length > 0).length;
      const ratio = filled / fields.length;
      const stage = Math.min(4, Math.floor(ratio * 5));
      scene.dataset.registerStage = String(stage);
      scene.style.setProperty('--auth-register-progress', ratio.toFixed(3));
    };

    if (isRegister && mainForm) {
      mainForm.addEventListener('input', updateRegisterProgress, { passive: true });
      mainForm.addEventListener('change', updateRegisterProgress, { passive: true });
      updateRegisterProgress();
    }

    mainForm?.addEventListener('submit', () => {
      scene.classList.add('is-authenticating');
      root.dataset.authSubmitting = 'true';
    });

    window.addEventListener('pageshow', () => {
      scene.classList.remove('is-authenticating');
      delete root.dataset.authSubmitting;
    });

    const errorFlash = card?.querySelector('.flash.error,.flash.bad,.flash.danger,.alert-danger,[data-auth-error="true"]');
    if (errorFlash) {
      root.dataset.authError = 'true';
      window.setTimeout(() => { delete root.dataset.authError; }, 1150);
    }

    const smallScreen = matchMedia('(max-width: 480px)');
    const mobileScreen = matchMedia('(max-width: 640px)');
    const coarsePointer = matchMedia('(pointer: coarse)');
    let liveRouteTimer = 0;
    let liveRouteSerial = 0;
    let lastLink = -1;

    const randomBetween = (min, max) => min + Math.random() * (max - min);

    const pulseNode = (nodeIndex, tone = 'violet') => {
      const node = constellation.nodeGroup.querySelector(`[data-node="${nodeIndex}"]`);
      if (!node) return;

      node.classList.remove('arrival-violet', 'arrival-blue', 'arrival-cyan', 'is-arrival');
      void node.getBBox?.();
      node.classList.add('is-arrival', `arrival-${tone}`);

      const connected = [
        ...constellation.edgeGroup.querySelectorAll(`[data-from="${nodeIndex}"],[data-to="${nodeIndex}"]`),
        ...constellation.registerEdges.querySelectorAll(`[data-from="${nodeIndex}"],[data-to="${nodeIndex}"]`)
      ];

      connected
        .sort(() => Math.random() - .5)
        .slice(0, smallScreen.matches ? 1 : 2)
        .forEach((edge, idx) => {
          const toneClass = `downstream-${tone}`;
          window.setTimeout(() => {
            edge.classList.remove('downstream-violet', 'downstream-blue', 'downstream-cyan');
            edge.classList.add('is-downstream', toneClass);
          }, 45 + idx * 72);
          window.setTimeout(() => {
            edge.classList.remove('is-downstream', toneClass);
          }, 760 + idx * 95);
        });

      window.setTimeout(() => {
        node.classList.remove('is-arrival', 'arrival-violet', 'arrival-blue', 'arrival-cyan');
      }, 820);
    };

    const emitLiveRoute = () => {
      if (
        document.hidden ||
        reduced.matches ||
        mobileScreen.matches ||
        root.dataset.workspaceMotion !== 'dynamic' ||
        root.dataset.authSubmitting === 'true'
      ) return;

      let linkIndex = Math.floor(Math.random() * links.length);
      if (links.length > 1 && linkIndex === lastLink) linkIndex = (linkIndex + 7) % links.length;
      lastLink = linkIndex;

      let [from, to] = links[linkIndex];
      if (Math.random() < .28) [from, to] = [to, from];

      const toneIndex = liveRouteSerial++ % 3;
      const tone = toneIndex === 0 ? 'violet' : (toneIndex === 1 ? 'blue' : 'cyan');
      const mobileVisual = smallScreen.matches || coarsePointer.matches;
      const duration = Math.round(randomBetween(
        mobileVisual ? 1450 : 1300,
        mobileVisual ? 1950 : 1850
      ));

      const path = svgEl('path', {
        d: curvedPath(from, to),
        class: `constellation-live-signal signal-${tone} signal-depth-${to % 3}`,
        'pathLength': '1',
        'data-from': from,
        'data-to': to
      });
      path.style.setProperty('--signal-duration', `${duration}ms`);
      constellation.liveGroup.append(path);

      const source = constellation.nodeGroup.querySelector(`[data-node="${from}"]`);
      source?.classList.add('is-sending');
      window.setTimeout(() => source?.classList.remove('is-sending'), 360);

      window.setTimeout(() => pulseNode(to, tone), Math.round(duration * .88));
      window.setTimeout(() => path.remove(), duration + 180);
    };

    const scheduleLiveRoute = (initial = false) => {
      window.clearTimeout(liveRouteTimer);
      if (mobileScreen.matches) return;
      const delay = initial ? 1100 : randomBetween(2500, 4700);

      liveRouteTimer = window.setTimeout(() => {
        emitLiveRoute();
        scheduleLiveRoute(false);
      }, delay);
    };

    let mobileTimer = 0;
    let mobileFrame = 0;
    let mobileSerial = 0;
    let lastMobileLink = -1;

    const clearMobileTransient = () => {
      window.clearTimeout(mobileTimer);
      if (mobileFrame) cancelAnimationFrame(mobileFrame);
      mobileFrame = 0;
      mobileGateway.live.replaceChildren();
      mobileGateway.nodeGroup.querySelectorAll('.is-mobile-arrival,.is-mobile-sending')
        .forEach(el => el.classList.remove('is-mobile-arrival','is-mobile-sending','mobile-violet','mobile-blue','mobile-cyan'));
      mobileGateway.edges.querySelectorAll('.is-mobile-active,.is-mobile-wake')
        .forEach(el => el.classList.remove('is-mobile-active','is-mobile-wake','mobile-violet','mobile-blue','mobile-cyan'));
    };

    const pulseMobileNode = (nodeIndex, tone, incomingEdge) => {
      const node = mobileGateway.nodeGroup.querySelector(`[data-mobile-node="${nodeIndex}"]`);
      if (!node) return;
      node.classList.remove('mobile-violet','mobile-blue','mobile-cyan','is-mobile-arrival');
      void node.getBBox?.();
      node.classList.add('is-mobile-arrival', `mobile-${tone}`);
      incomingEdge?.classList.remove('is-mobile-active');
      incomingEdge?.classList.add('is-mobile-wake', `mobile-${tone}`);

      const outgoing = [...mobileGateway.edges.querySelectorAll(`[data-from="${nodeIndex}"],[data-to="${nodeIndex}"]`)]
        .filter(el => el !== incomingEdge);
      if (outgoing.length) {
        const next = outgoing[Math.floor(Math.random() * outgoing.length)];
        window.setTimeout(() => next.classList.add('is-mobile-wake', `mobile-${tone}`), 90);
        window.setTimeout(() => next.classList.remove('is-mobile-wake', `mobile-${tone}`), 720);
      }
      window.setTimeout(() => {
        node.classList.remove('is-mobile-arrival', `mobile-${tone}`);
        incomingEdge?.classList.remove('is-mobile-wake', `mobile-${tone}`);
      }, 820);
    };

    const emitMobileRoute = () => {
      if (!mobileScreen.matches || document.hidden || reduced.matches ||
          root.dataset.workspaceMotion !== 'dynamic' || root.dataset.authSubmitting === 'true') return;

      let linkIndex = Math.floor(Math.random() * mobileLinks.length);
      if (mobileLinks.length > 1 && linkIndex === lastMobileLink) linkIndex = (linkIndex + 3) % mobileLinks.length;
      lastMobileLink = linkIndex;
      let [from,to] = mobileLinks[linkIndex];
      if (Math.random() < .24) [from,to] = [to,from];

      const tone = ['violet','blue','cyan'][mobileSerial++ % 3];
      const edge = mobileGateway.edges.querySelector(`[data-mobile-link="${linkIndex}"]`);
      const source = mobileGateway.nodeGroup.querySelector(`[data-mobile-node="${from}"]`);
      if (!edge || !source) return;

      edge.classList.add('is-mobile-active', `mobile-${tone}`);
      source.classList.add('is-mobile-sending', `mobile-${tone}`);
      window.setTimeout(() => source.classList.remove('is-mobile-sending', `mobile-${tone}`), 360);

      const packet = svgEl('circle', { r:'3.7', class:`mobile-gateway-packet mobile-${tone}` });
      mobileGateway.live.append(packet);
      const length = Math.max(1, edge.getTotalLength());
      const duration = Math.round(randomBetween(1350, 1850));
      const started = performance.now();

      const step = now => {
        if (!packet.isConnected || document.hidden || !mobileScreen.matches || root.dataset.workspaceMotion !== 'dynamic') {
          packet.remove();
          edge.classList.remove('is-mobile-active', `mobile-${tone}`);
          return;
        }
        const raw = Math.min(1, (now - started) / duration);
        const eased = raw < .5 ? 2 * raw * raw : 1 - Math.pow(-2 * raw + 2, 2) / 2;
        const point = edge.getPointAtLength(length * eased);
        packet.setAttribute('cx', point.x.toFixed(2));
        packet.setAttribute('cy', point.y.toFixed(2));
        packet.style.opacity = String(Math.min(1, raw * 7, (1 - raw) * 8));
        if (raw < 1) {
          mobileFrame = requestAnimationFrame(step);
        } else {
          packet.remove();
          mobileFrame = 0;
          pulseMobileNode(to, tone, edge);
        }
      };
      mobileFrame = requestAnimationFrame(step);
    };

    const scheduleMobileRoute = (initial = false) => {
      window.clearTimeout(mobileTimer);
      if (!mobileScreen.matches || reduced.matches) return;
      const delay = initial ? 650 : randomBetween(2500, 3900);
      mobileTimer = window.setTimeout(() => {
        emitMobileRoute();
        scheduleMobileRoute(false);
      }, delay);
    };

    const resetLiveMotion = () => {
      clearMobileTransient();
      constellation.liveGroup.replaceChildren();
      scene.querySelectorAll('.constellation-node-wrap.is-arrival,.constellation-node-wrap.is-sending')
        .forEach(el => el.classList.remove('is-arrival','is-sending','arrival-violet','arrival-blue','arrival-cyan'));
      scene.querySelectorAll('.constellation-edge.is-downstream,.constellation-register-edges path.is-downstream')
        .forEach(el => el.classList.remove('is-downstream','downstream-violet','downstream-blue','downstream-cyan'));
      if (mobileScreen.matches) scheduleMobileRoute(true);
      else scheduleLiveRoute(true);
    };

    if (mobileScreen.matches) scheduleMobileRoute(true);
    else scheduleLiveRoute(true);
    smallScreen.addEventListener?.('change', resetLiveMotion);
    mobileScreen.addEventListener?.('change', () => { setParallax?.(0,0); resetLiveMotion(); });
    coarsePointer.addEventListener?.('change', resetLiveMotion);
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        if (mobileScreen.matches) scheduleMobileRoute(true);
        else scheduleLiveRoute(true);
      }
    });

    let pointerFrame = 0;
    const setParallax = (x, y) => {
      const put = (name, value) => scene.style.setProperty(name, `${value.toFixed(2)}px`);
      put('--auth-px-far', x * .16);
      put('--auth-py-far', y * .16);
      put('--auth-px-near-neg', x * -.32);
      put('--auth-py-near-neg', y * -.32);
      put('--auth-px-main', x * .18);
      put('--auth-py-main', y * .18);
      put('--auth-px-far2', x * .15);
      put('--auth-py-far2', y * .15);
      put('--auth-px-mid-neg', x * -.17);
      put('--auth-py-mid-neg', y * -.17);
      put('--auth-px-near2-neg', x * -.33);
      put('--auth-py-near2-neg', y * -.33);
    };

    const pointerMove = event => {
      if (
        reduced.matches ||
        mobileScreen.matches ||
        coarsePointer.matches ||
        root.dataset.workspaceMotion !== 'dynamic'
      ) return;
      if (pointerFrame) cancelAnimationFrame(pointerFrame);
      pointerFrame = requestAnimationFrame(() => {
        const dx = ((event.clientX / Math.max(1, innerWidth)) - .5) * 14;
        const dy = ((event.clientY / Math.max(1, innerHeight)) - .5) * 10;
        setParallax(dx, dy);
      });
    };

    window.addEventListener('pointermove', pointerMove, { passive: true });
    window.addEventListener('pointerleave', () => setParallax(0, 0), { passive: true });


    scheme.addEventListener?.('change', paint);
    reduced.addEventListener?.('change', () => {
      if (reduced.matches) {
        setParallax(0, 0);
        resetLiveMotion();
      }
    });
    smallScreen.addEventListener?.('change', () => setParallax(0, 0));
    coarsePointer.addEventListener?.('change', () => setParallax(0, 0));
    readTheme();
    paint();
  }

  document.addEventListener('DOMContentLoaded', setupModernAuth, { once: true });
})();
