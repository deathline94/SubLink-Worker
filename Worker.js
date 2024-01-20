addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  // Define the text you want to return . One link per line.
  const text = `
  // Put the links here . One link per line...
`;

  // Return the text as a response
  return new Response(text, {
    headers: { "content-type": "text/plain" },
  });
}
