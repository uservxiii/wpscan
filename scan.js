const PROXY = "https://r.jina.ai/http://";

const out = t => document.getElementById("result").textContent = t;
const clean = d => d.replace(/^https?:\/\//,'').replace(/\/.*$/,'');

async function hybridFetch(url, timeout = 6000){
  const ctrl = new AbortController();
  setTimeout(()=>ctrl.abort(), timeout);

  try{
    return { res: await fetch(url, {signal: ctrl.signal}), mode: "direct" };
  }catch{
    try{
      return { res: await fetch(PROXY + url.replace(/^https?:\/\//,'')), mode: "proxy" };
    }catch{
      return null;
    }
  }
}

async function scan(){
  const domain = clean(document.getElementById("target").value.trim());
  if(!domain) return alert("Masukkan domain");

  out("Scanning...");
  let log = `Target\n------\n${domain}\n\n`;

  const base = "https://" + domain;

  // HOME
  const home = await hybridFetch(base);
  if(!home){ out("Target unreachable."); return; }

  const html = await home.res.text();
  log += `Fetch Mode\n----------\n${home.mode}\n\n`;

  // WP detect
  const isWP = /wp-content|wp-includes/i.test(html);
  log += `WordPress Detected\n------------------\n${isWP?"YES":"NO"}\n\n`;

  // Admin paths
  log += "Admin Login Paths\n-----------------\n";
  for(const p of ["/wp-login.php","/wp-admin/"]){
    const r = await hybridFetch(base+p);
    log += `${p} => ${r ? r.res.status : "blocked"}\n`;
  }

  // XMLRPC
  const xr = await hybridFetch(base+"/xmlrpc.php");
  log += `\nXML-RPC\n-------\n${xr ? xr.res.status : "blocked"}\n`;

  // REST
  const restUsers = await hybridFetch(base+"/wp-json/wp/v2/users");
  log += `\nwp-json Mapper\n--------------\n`;
  log += `/wp-json/ => ${(await hybridFetch(base+"/wp-json/"))?.res.status || "blocked"}\n`;
  log += `/wp-json/wp/v2/users => ${restUsers ? restUsers.res.status : "blocked"}\n`;

  // User enum
  log += `\nUser Enumeration (Passive)\n-------------------------\n`;
  let status = "Protected";
  let users = [];

  if(restUsers && restUsers.res.status === 200){
    try{
      const data = await restUsers.res.json();
      if(Array.isArray(data) && data.length){
        status = "Exposed (REST API)";
        data.forEach(u => users.push(`- ${u.slug}`));
      }
    }catch{}
  }

  const author = await hybridFetch(base + "/?author=1");
  if(author && author.res.url.includes("/author/")){
    status = "Exposed (Author Archive)";
  }

  log += `Status: ${status}\n`;
  if(users.length) log += users.join("\n") + "\n";

  // Plugins
  const plugins = [...new Set(
    [...html.matchAll(/wp-content\/plugins\/([a-z0-9-_]+)/gi)].map(m=>m[1])
  )];

  log += `\nPlugins Detected\n----------------\n`;
  log += plugins.length ? plugins.join(", ") : "None";

  out(log);
}
