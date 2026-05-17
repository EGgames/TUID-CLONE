/* Ocultar formulario cuando el resultado ya está visible (POST exitoso) */
document.addEventListener('DOMContentLoaded', function () {
  var result = document.getElementById('signResult');
  if (result && getComputedStyle(result).display !== 'none') {
    var form = document.querySelector('form[action="/sign"]');
    var divider = form && form.previousElementSibling;
    if (divider && divider.classList.contains('divider')) divider.style.display = 'none';
    if (form) form.style.display = 'none';
  }

  var tokenEl = document.getElementById('tokenVal');
  if (tokenEl) tokenEl.addEventListener('click', function () { this.select(); });

  var btnPdf = document.getElementById('btnPdf');
  if (btnPdf) btnPdf.addEventListener('click', generarPDF);
});

function generarPDF() {
  if (!window.jspdf) {
    alert('Librería PDF no disponible. Asegúrate de tener conexión a internet y recarga la página.');
    return;
  }
  const { jsPDF } = window.jspdf;

  /* Extrae texto de un elemento: primero por ID, luego por selector CSS */
  function extraer(id, sel) {
    const porId = document.getElementById(id);
    if (porId) {
      const v = porId.textContent.trim();
      if (v && !v.startsWith('__')) return v;
    }
    const porSel = document.querySelector(sel);
    if (porSel) {
      const v = porSel.textContent.trim();
      if (v && !v.startsWith('__')) return v;
    }
    return '';
  }

  /* Busca el valor de un campo en el grid por su etiqueta visible */
  function extraerPorEtiqueta(etiqueta) {
    const items = document.querySelectorAll('#signResult .info-item');
    for (const item of items) {
      const lbl = item.querySelector('.info-label');
      if (lbl && lbl.textContent.trim() === etiqueta) {
        const val = item.querySelector('.info-value');
        return val ? val.textContent.trim() : '';
      }
    }
    return '';
  }

  const signer = extraer('signerVal', '#signResult .info-item:first-child .info-value')
              || extraerPorEtiqueta('Firmante');
  const ci     = extraer('ciVal',  '#signResult .info-item:nth-child(2) .info-value')
              || extraerPorEtiqueta('Cédula');
  const ts     = extraer('tsVal',  '#signResult .info-item:nth-child(3) .info-value')
              || extraerPorEtiqueta('Fecha y hora (UTC)');
  const txt    = (() => {
    const el = document.getElementById('textVal') || document.querySelector('#signResult pre.signed-text');
    return el ? el.textContent.trim() : '';
  })();
  const token  = (() => {
    const el = document.getElementById('tokenVal') || document.querySelector('#signResult textarea[readonly]');
    return el ? el.value.trim() : '';
  })();

  /* Verificar que hay datos reales (no placeholders sin reemplazar) */
  const resultDiv = document.getElementById('signResult');
  const resultVisible = resultDiv && resultDiv.style.display !== 'none';
  if (!resultVisible || !signer) {
    alert('Primero firma un documento para poder descargar el certificado.');
    return;
  }

  // Truncar texto largo para el PDF (el token ya contiene todo)
  const MAX_TXT = 500;
  const txtPdf = txt.length > MAX_TXT
    ? txt.slice(0, MAX_TXT) + '\n[... texto truncado. Versión completa en el token de verificación]'
    : txt;

  const doc = new jsPDF({ orientation: 'p', unit: 'mm', format: 'a4' });
  const W   = doc.internal.pageSize.getWidth();
  const H   = doc.internal.pageSize.getHeight();
  const M   = 18;
  const CW  = W - M * 2;
  let   y   = 0;

  // Fondo oscuro
  doc.setFillColor(10, 8, 24);
  doc.rect(0, 0, W, H, 'F');

  // Barra de cabecera morada
  doc.setFillColor(80, 30, 180);
  doc.rect(0, 0, W, 44, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.setTextColor(255, 255, 255);
  doc.text('CERTIFICADO DE FIRMA DIGITAL', W / 2, 16, { align: 'center' });

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(200, 180, 255);
  doc.text('Sistema ID_LOGIN  \u00b7  RSA-2048 PSS/SHA-256  \u00b7  ISO 27001', W / 2, 26, { align: 'center' });

  doc.setFontSize(7);
  doc.setTextColor(170, 150, 230);
  const genDate = new Date().toISOString().replace('T',' ').slice(0,19) + ' UTC';
  doc.text('Generado: ' + genDate, W / 2, 36, { align: 'center' });

  y = 52;

  // Bloque de datos
  doc.setFillColor(20, 15, 48);
  doc.setDrawColor(90, 55, 175);
  doc.setLineWidth(0.4);
  doc.roundedRect(M, y, CW, 62, 3, 3, 'FD');

  const fld = (label, value, fx, fy, fw) => {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(150, 110, 230);
    doc.text(label, fx, fy);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.setTextColor(230, 220, 255);
    const lines = doc.splitTextToSize(value || '\u2014', fw);
    doc.text(lines, fx, fy + 5);
    return fy + 5 + lines.length * 5.5;
  };

  const half = CW / 2 - 5;
  fld('FIRMANTE', signer, M + 8, y + 10, half);
  fld('C\u00c9DULA DE IDENTIDAD', ci, M + 8 + half + 10, y + 10, half - 10);
  fld('FECHA Y HORA (UTC)', ts, M + 8, y + 30, CW - 16);
  fld('ALGORITMO', 'RSA-2048 \u00b7 Padding PSS \u00b7 Digest SHA-256 \u00b7 Salt MAX_LENGTH', M + 8, y + 46, CW - 16);

  y += 70;

  // Contenido firmado
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(150, 110, 230);
  doc.text('CONTENIDO FIRMADO', M, y);
  y += 5;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.setTextColor(220, 215, 245);
  const textLines = doc.splitTextToSize(txtPdf || '\u2014', CW - 14);
  const textH     = textLines.length * 5.5 + 14;
  doc.setFillColor(18, 14, 38);
  doc.setDrawColor(80, 50, 160);
  doc.setLineWidth(0.3);
  doc.roundedRect(M, y, CW, textH, 2, 2, 'FD');
  doc.text(textLines, M + 7, y + 8);
  y += textH + 10;

  // Token
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(150, 110, 230);
  doc.text('TOKEN DE VERIFICACI\u00d3N', M, y);
  y += 5;

  doc.setFont('courier', 'normal');
  doc.setFontSize(6);
  doc.setTextColor(160, 145, 210);
  const tokLines = doc.splitTextToSize(token || '\u2014', CW - 14);
  const tokH     = tokLines.length * 4 + 12;
  doc.setFillColor(15, 10, 35);
  doc.setDrawColor(60, 40, 130);
  doc.setLineWidth(0.3);
  doc.roundedRect(M, y, CW, tokH, 2, 2, 'FD');
  doc.text(tokLines, M + 7, y + 7);
  y += tokH + 10;

  // URL de verificación
  if (y < H - 20) {
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(7);
    doc.setTextColor(110, 90, 170);
    doc.text('Verificar autenticidad en: ' + window.location.origin + '/verify', M, y);
  }

  // Pie de página
  doc.setFillColor(50, 20, 130);
  doc.rect(0, H - 12, W, 12, 'F');
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(190, 170, 230);
  doc.text('Firma criptogr\u00e1fica RSA-2048 generada por Sistema ID_LOGIN', W / 2, H - 4.5, { align: 'center' });

  const safeName = signer.toLowerCase().replace(/[\s\/\\:*?"<>|]/g, '_').slice(0, 20);
  doc.save('certificado_' + safeName + '_' + Date.now() + '.pdf');
}
