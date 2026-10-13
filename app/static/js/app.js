document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.querySelector('.mobile-toggle');
  toggle?.addEventListener('click', () => {
    const sidebar = toggle.closest('.sidebar');
    const open = sidebar.classList.toggle('is-open');
    toggle.setAttribute('aria-expanded', String(open));
  });
  // Associate legacy form labels with controls without changing names/contracts.
  document.querySelectorAll('input:not([type=hidden]),textarea,select').forEach((el, i) => {
    if (!el.id) el.id = 'field-' + i;
    const label = el.closest('.form-group')?.querySelector('label') || el.parentElement?.querySelector('label');
    if (label && !label.htmlFor) label.htmlFor = el.id;
  });
});
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-confirm]').forEach(el => {
    el.addEventListener(el.tagName === 'FORM' ? 'submit' : 'click', event => {
      if (!window.confirm(el.dataset.confirm)) event.preventDefault();
    });
  });
  document.querySelectorAll('[data-copy]').forEach(button => {
    button.addEventListener('click', async () => {
      const input = document.getElementById(button.dataset.copy);
      if (!input) return;
      try {
        await navigator.clipboard.writeText(input.value);
        button.textContent = 'Скопировано';
      } catch (_) {
        input.focus(); input.select();
        button.textContent = 'Ctrl+C для копирования';
      }
    });
  });
  document.querySelectorAll('[data-verify-dns]').forEach(button => {
    button.addEventListener('click', async () => {
      const result = document.getElementById('verify-result');
      button.disabled = true;
      result.hidden = true;
      try {
        const response = await fetch('/admin/sites/' + encodeURIComponent(button.dataset.verifyDns) + '/dns/verify');
        if (!response.ok) throw new Error('HTTP ' + response.status);
        const data = await response.json();
        for (const [type, info] of Object.entries(data.records)) {
          if (!/^[a-z]+$/.test(type)) continue;
          const cell = document.querySelector('.dns-status[data-type="' + type + '"]');
          if (!cell) continue;
          const badge = document.createElement('span'); badge.className = 'badge';
          badge.textContent = ({verified:'Настроено',warning:'Частично',missing:'Не найдено'})[info.status] || 'Не найдено';
          const detail = document.createElement('p'); detail.className = 'muted'; detail.textContent = info.detail;
          cell.replaceChildren(badge, detail);
        }
        result.textContent = data.all_verified ? 'DNS записи настроены. Доставляемость требует отдельной проверки.' : 'Некоторые DNS записи не настроены. Изменения могут обновляться до 24 часов.';
      } catch (error) {
        result.textContent = 'Не удалось проверить DNS: ' + error.message;
      } finally {
        result.hidden = false; result.classList.add('notice');
        result.classList.remove('legacy-9');
        button.disabled = false;
      }
    });
  });
});
