try { var t = localStorage.getItem('fortres-theme'); if (t) document.documentElement.dataset.theme = t; } catch (e) {}
document.documentElement.classList.add('js');
