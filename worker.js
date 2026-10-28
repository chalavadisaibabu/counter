
export default {
  async fetch(request, env, ctx) {
    return new Response("Cafeteria Display Worker is running!", {
      headers: { "content-type": "text/plain" },
    });
  },
};
