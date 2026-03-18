/**
 * pypki_ui.js — shared UI utilities for PyPKI web interface.
 * Requires Bootstrap 5 JS bundle to already be loaded on the page.
 */
(function () {

  // ── Toast notifications ────────────────────────────────────────────────
  let _toastContainer = null;

  function _getToastContainer() {
    if (!_toastContainer) {
      _toastContainer = document.createElement('div');
      _toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
      _toastContainer.style.zIndex = 1100;
      document.body.appendChild(_toastContainer);
    }
    return _toastContainer;
  }

  /**
   * showToast(message, type)
   * type: 'success' | 'danger' | 'warning' | 'info'
   */
  window.showToast = function (message, type = 'success') {
    const icons = {
      success: 'bi-check-circle-fill',
      danger:  'bi-x-circle-fill',
      warning: 'bi-exclamation-triangle-fill',
      info:    'bi-info-circle-fill',
    };
    const el = document.createElement('div');
    el.className = `toast align-items-center text-bg-${type} border-0`;
    el.setAttribute('role', 'alert');
    el.innerHTML = `
      <div class="d-flex">
        <div class="toast-body">
          <i class="bi ${icons[type] || icons.info} me-2"></i>${message}
        </div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto"
                data-bs-dismiss="toast"></button>
      </div>`;
    _getToastContainer().appendChild(el);
    const toast = new bootstrap.Toast(el, { delay: 4000 });
    toast.show();
    el.addEventListener('hidden.bs.toast', () => el.remove());
  };

  // ── Confirmation modal ─────────────────────────────────────────────────
  let _confirmEl = null;

  function _ensureConfirmModal() {
    if (_confirmEl) return;
    _confirmEl = document.createElement('div');
    _confirmEl.id = '_pypkiConfirmModal';
    _confirmEl.className = 'modal fade';
    _confirmEl.tabIndex = -1;
    _confirmEl.innerHTML = `
      <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="_pypkiConfirmTitle">Confirm</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
          </div>
          <div class="modal-body" id="_pypkiConfirmBody"></div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
            <button type="button" class="btn" id="_pypkiConfirmOk">Confirm</button>
          </div>
        </div>
      </div>`;
    document.body.appendChild(_confirmEl);
  }

  /**
   * confirmAction(message, options) → Promise<boolean>
   * options: { title, okLabel, okClass }
   */
  window.confirmAction = function (message, { title = 'Confirm', okLabel = 'Confirm', okClass = 'btn-danger' } = {}) {
    return new Promise(resolve => {
      _ensureConfirmModal();
      document.getElementById('_pypkiConfirmTitle').textContent = title;
      document.getElementById('_pypkiConfirmBody').innerHTML   = message;
      const okBtn = document.getElementById('_pypkiConfirmOk');
      okBtn.textContent = okLabel;
      okBtn.className   = `btn ${okClass}`;

      let confirmed = false;
      const onOk   = () => { confirmed = true; bootstrap.Modal.getInstance(_confirmEl).hide(); };
      const onHide = () => {
        okBtn.removeEventListener('click', onOk);
        _confirmEl.removeEventListener('hidden.bs.modal', onHide);
        resolve(confirmed);
      };
      okBtn.addEventListener('click', onOk, { once: true });
      _confirmEl.addEventListener('hidden.bs.modal', onHide, { once: true });
      new bootstrap.Modal(_confirmEl).show();
    });
  };

})();
