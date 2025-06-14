window.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.copy-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var code = btn.parentElement.nextElementSibling;
      if (code) {
        navigator.clipboard.writeText(code.innerText).then(function() {
          var original = btn.textContent;
          btn.textContent = 'Copied';
          setTimeout(function(){ btn.textContent = original; }, 2000);
        });
      }
    });
  });
});
