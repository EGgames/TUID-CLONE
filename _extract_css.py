import re, os

BASE = r"C:\Users\emili\OneDrive\Desktop\ID_LOGIN"

pages = {
    "index": ("frontend/pages/index.html", "frontend/css/login.css"),
    "dashboard": ("frontend/pages/dashboard.html", "frontend/css/dashboard.css"),
    "register": ("frontend/pages/register.html", "frontend/css/register.css"),
    "setup-ci": ("frontend/pages/setup-ci.html", "frontend/css/setup-ci.css"),
    "sign": ("frontend/pages/sign.html", "frontend/css/sign.css"),
    "verify": ("frontend/pages/verify.html", "frontend/css/verify.css"),
}

for name, (html_rel, css_rel) in pages.items():
    html_path = os.path.join(BASE, html_rel.replace("/", os.sep))
    css_path = os.path.join(BASE, css_rel.replace("/", os.sep))
    
    if not os.path.exists(html_path):
        print(f"ERROR: {html_path} does not exist.")
        continue

    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()
    
    # Extract <style> content (possibly multiple blocks)
    style_blocks = re.findall(r'<style[^>]*>(.*?)</style>', html, re.DOTALL)
    
    if not style_blocks:
        print(f"WARNING: No <style> found in {name}")
        # Proceed anyway to add CSRF and other updates
    
    if style_blocks:
        css_content = "\n".join(style_blocks)
        
        # Write CSS file
        os.makedirs(os.path.dirname(css_path), exist_ok=True)
        with open(css_path, "w", encoding="utf-8") as f:
            f.write(css_content)
        print(f"Created: {css_rel} ({len(css_content)} chars)")
        
        # Determine CSS URL path for link tag
        css_url = "/" + css_rel.replace("\\", "/").replace("frontend/", "")
        
        # Replace ALL <style>...</style> blocks with single <link> tag
        html_no_style = re.sub(r'\s*<style[^>]*>.*?</style>', '', html, flags=re.DOTALL)
        link_tag = f'  <link rel="stylesheet" href="{css_url}">'
        html_to_process = html_no_style.replace('</head>', f'{link_tag}\n</head>', 1)
    else:
        html_to_process = html
    
    # Add CSRF hidden input to forms
    csrf_input = '\n    <input type="hidden" name="csrf_token" value="__CSRF_TOKEN__">'
    
    def add_csrf(m):
        return m.group(0) + csrf_input
    
    html_with_csrf = re.sub(r'<form\b[^>]*>', add_csrf, html_to_process)
    
    # For register.html: add register_key input before the submit button
    if name == "register":
        register_key_field = '''
    <!-- Campo de clave de registro (requerido si REGISTER_KEY está definido en el servidor) -->
    <div class="form-group" id="regKeyGroup" style="display:none">
      <label for="register_key">Clave de Registro</label>
      <div class="input-wrapper">
        <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
        </svg>
        <input type="password" id="register_key" name="register_key"
               placeholder="Clave proporcionada por el administrador"
               maxlength="128" autocomplete="off" />
      </div>
    </div>'''
        # Insert before the submit button
        html_with_csrf = html_with_csrf.replace(
            '<button type="submit"',
            register_key_field + '\n    <button type="submit"',
            1
        )
        # Add JS to show/hide regKeyGroup based on __REGKEY_REQUIRED__ placeholder
        regkey_js = '''
<script>
(function(){
  var req = "__REGKEY_REQUIRED__";
  if(req === "1"){
    var g = document.getElementById("regKeyGroup");
    if(g){ g.style.display = "block"; }
    var inp = document.getElementById("register_key");
    if(inp){ inp.required = true; }
  }
})();
</script>'''
        html_with_csrf = html_with_csrf.replace('</body>', regkey_js + '\n</body>', 1)
    
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_with_csrf)
    print(f"Updated: {html_rel}")

print("\nAll done.")
