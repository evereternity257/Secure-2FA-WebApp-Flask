self.addEventListener('fetch', function(event) {
  // Bỏ qua để Service Worker hoạt động mượt mà với Flask
  event.respondWith(fetch(event.request));
});