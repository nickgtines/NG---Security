const js = (await Bun.file('./bundle.js').text()).replaceAll('</script', '<\\/script');
const css = await Bun.file('./output.css').text();
const rawTitle = (process.env.ROUTE_PATH ?? '').replace(/^\//, '') || 'Home';
const basePath = process.env._3B_BRANCH_ID
  ? `/__3b/branch/${process.env._3B_BRANCH_ID}${process.env.ROUTE_PATH ?? ''}`
  : process.env.ROUTE_PATH ?? '';
const title = rawTitle.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

console.log(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.ico?t=${encodeURIComponent(rawTitle)}">
  <style>${css}</style>
</head>
<body>
  <div id="root"></div>
  <script>window.__ROUTE_PATH__=${JSON.stringify(basePath).replaceAll('</script', '<\\/script')};</script>
  <script type="module">${js}</script>
</body>
</html>`);
