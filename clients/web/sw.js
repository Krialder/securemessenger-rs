// Service Worker fuer Web-Push (F1).
//
// Der Aufweck-Push ist INHALTSLOS (der Server sendet keinen verschluesselten
// Payload, siehe services/delivery/src/push.rs): der Worker zeigt darum eine
// generische Meldung, die eigentliche Nachricht holt die App selbst per Pull,
// sobald sie im Vordergrund ist. So sieht weder der fremde Push-Dienst noch
// dieser Worker den Chat-Inhalt.

self.addEventListener('push', (event) => {
  // event.data ist null (inhaltslos). Eine bewusst nichtssagende Meldung,
  // damit die Benachrichtigung selbst nichts ueber Absender oder Inhalt
  // verraet.
  const title = 'SecureMessenger';
  const options = {
    body: 'Neue Nachricht. Zum Lesen oeffnen.',
    tag: 'sm-new-message', // buendelt mehrere Pushs zu einer Meldung
    icon: '/favicon.ico',
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

// Klick auf die Benachrichtigung: ein vorhandenes App-Fenster fokussieren,
// sonst eines oeffnen.
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients
      .matchAll({ type: 'window', includeUncontrolled: true })
      .then((clientList) => {
        for (const client of clientList) {
          if ('focus' in client) {
            return client.focus();
          }
        }
        if (self.clients.openWindow) {
          return self.clients.openWindow('/');
        }
        return undefined;
      })
  );
});
