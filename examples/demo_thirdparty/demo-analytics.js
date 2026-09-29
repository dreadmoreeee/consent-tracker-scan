// "Demo Analytics": a fake tracker that behaves like a typical analytics tag.
(function () {
  var id = "DA1." + Math.floor(Math.random() * 1e9);
  // First-party cookie written by a third-party script (like _ga).
  document.cookie = "_da_id=" + id + "; path=/; max-age=63072000; SameSite=Lax";
  localStorage.setItem("_da_last_visit", String(Date.now()));
  // Beacon to the tracker's own host; its response sets a third-party cookie.
  new Image().src = "{{TRACKER}}/collect?cid=" + id + "&dl=" + encodeURIComponent(location.href);
})();
