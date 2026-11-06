// Local stateful subset of Cloudflare DNS API; never deploy or use real tokens.
const http = require("node:http");
let mode = "ok";
let rows = [];
let posts = 0;
let reads = [];
let writes = 0;
let sequence = 1;
let injected = false;
const zone = "a".repeat(32);
const id = "b".repeat(32);
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  const reply = (status, result) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        success: status === 200,
        errors: [],
        messages: [],
        result,
        result_info: {
          total_pages: 1,
          count: Array.isArray(result) ? result.length : 1,
        },
      }),
    );
  };
  if (url.pathname.startsWith("/client/v4/__control/")) {
    mode = url.pathname.split("/").pop();
    rows = [];
    sequence = 1; injected = false;
    posts = 0;
    reads = [];
    writes = 0;
    if (mode.startsWith("v2-")) {
      const add = (name,type,content) => rows.push({id:(sequence++).toString(16).padStart(32,"0"),name,type,content,proxied:true,ttl:1});
      if (["v2-replace","v2-unknown-delete","v2-unknown-patch","v2-preserve"].includes(mode)) {
        add("example.com","AAAA","2001:db8::20");
        add("example.com","A","192.0.2.20");
        add("example.com","A","192.0.2.21");
        add("*.example.com","A","192.0.2.20");
        add("admin.example.com","A","192.0.2.20");
        add("mail.example.com","A","192.0.2.40");
        add("example.com","MX","mail.example.com");
        add("example.com","TXT","keep-me");
      }
      if(mode === "v2-unrelated") add("admin.example.com","TXT","keep-me");
      if(mode === "v2-delegated") add("admin.example.com","NS","ns.example.net");
    }
    if (mode === "conflict")
      rows = [
        {
          id,
          name: "admin.example.com",
          type: "A",
          content: "192.0.2.20",
          proxied: true,
        },
      ];
    if (mode.startsWith("wildcard") || mode.startsWith("nested")) {
      const record = (name, type, content, proxied = true) => ({
        id, name, type, content, proxied,
      });
      rows = [
        record("example.com", "A", "192.0.2.10"),
        record("*.example.com", "CNAME", "example.com"),
      ];
      if (mode === "wildcard-dns-only") rows[1].proxied = false;
      if (mode === "wildcard-bad-origin") rows[0].content = "192.0.2.20";
      if (mode === "wildcard-extra-family")
        rows.push(record("example.com", "AAAA", "2001:db8::10"));
      if (mode === "wildcard-ipv6") rows[0] = record("example.com", "AAAA", "2001:db8::10");
      if (mode === "wildcard-dual") rows.push(record("example.com", "AAAA", "2001:db8::10"));
      if (mode === "wildcard-direct-address") rows[1] = record("*.example.com", "A", "192.0.2.10");
      if (mode === "wildcard-chain") {
        rows[0] = record("example.com", "CNAME", "origin.example.com.");
        rows.push(record("origin.example.com", "A", "192.0.2.10"));
      }
      if (mode === "wildcard-loop") rows[0] = record("example.com", "CNAME", "admin.example.com");
      if (mode === "wildcard-external") rows[1].content = "origin.example.net";
      if (mode === "wildcard-missing") rows = [rows[1]];
      if (mode === "wildcard-specific-conflict")
        rows.push(record("admin.example.com", "A", "192.0.2.20"));
      if (mode === "wildcard-exact-txt")
        rows.push(record("admin.example.com", "TXT", "existing-node"));
      if (mode === "nested-parent-block" || mode === "nested-specific")
        rows.push(record("sub.example.com", "TXT", "existing-node"));
      if (mode === "nested-specific")
        rows.push(record("*.sub.example.com", "CNAME", "example.com"));
      if (mode === "nested-delegated")
        rows.push(record("sub.example.com", "NS", "ns.example.net"));
      if (mode === "nested-specific-conflict") {
        rows.push(record("*.sub.example.com", "CNAME", "wrong.example.com"));
        rows.push(record("wrong.example.com", "A", "192.0.2.20"));
      }
      if (mode === "wildcard-target-delegated") {
        rows[1].content = "origin.sub.example.com";
        rows.push(record("origin.sub.example.com", "A", "192.0.2.10"));
        rows.push(record("sub.example.com", "NS", "ns.example.net"));
      }
    }
    return reply(200, []);
  }
  if (url.pathname === "/client/v4/__txt")
    return reply(200, rows.filter(row => row.type === "TXT" && row.name.startsWith("_acme-challenge.")));
  if (url.pathname === "/client/v4/__mutate" && mode.startsWith("v2-")) {
    const row = rows.find(row => row.type === "A" && row.name === "example.com");
    if(row) row.content = "192.0.2.99";
    return reply(200, rows);
  }
  if(mode.startsWith("v2-") && url.pathname.startsWith(`/client/v4/zones/${zone}/dns_records`)) {
    const recordId = url.pathname.split("/dns_records/")[1];
    if(req.method === "GET") {
      if(recordId) {
        const row = rows.find(row => row.id === recordId);
        if(!row) {
          res.writeHead(404,{"Content-Type":"application/json"});
          return res.end(JSON.stringify({success:false,errors:[{code:81044}]}));
        }
        return reply(200,row);
      }
      const name = url.searchParams.get("name");
      if(!name) return reply(400,[]);
      reads.push(name);
      if(mode === "v2-read-denied") return reply(403,[]);
      if(mode === "v2-incomplete") {
        res.writeHead(200,{"Content-Type":"application/json"});
        return res.end(JSON.stringify({success:true,result:[],result_info:{total_pages:2}}));
      }
      return reply(200, rows.filter(row => row.name === name));
    }
    writes++;
    if(req.method === "POST") posts++;
    if(mode === "v2-denied") return reply(403,[]);
    let body=req.body;
    if(!body) { let text=""; for await(const chunk of req) text+=chunk; try { body=text ? JSON.parse(text) : {}; } catch { return reply(400,[]); } }
    if(typeof body === "string") { try {body=JSON.parse(body);} catch {return reply(400,[]);} }
    if(req.method === "DELETE") {
      const row=rows.find(row=>row.id===recordId);
      if(!row) return reply(404,[]);
      rows=rows.filter(row=>row.id!==recordId);
      if(mode === "v2-unknown-delete" && !injected) {injected=true;return reply(500,[]);}
      return reply(200,{id:recordId});
    }
    if(!["A","AAAA","CNAME","TXT"].includes(body.type) || typeof body.comment !== "string") return reply(400,[]);
    if(mode === "v2-unknown-uncommitted" && !injected) {injected=true;return reply(500,[]);}
    if(req.method === "POST") {
      if(body.type !== "TXT" && rows.some(row => row.name===body.name && (row.type===body.type || row.type === "CNAME" || body.type==="CNAME"))) return reply(400,[]);
      const row={...body,id:(sequence++).toString(16).padStart(32,"0")}; rows.push(row);
      if(mode === "v2-unknown-committed" && !injected) {injected=true;return reply(500,[]);}
      return reply(200,row);
    }
    if(req.method === "PATCH") {
      const index=rows.findIndex(row=>row.id===recordId); if(index<0)return reply(404,[]);
      rows[index]={...rows[index],...body};
      if(mode === "v2-unknown-patch" && !injected) {injected=true;return reply(500,[]);}
      return reply(200,rows[index]);
    }
    return reply(501,[]);
  }
  if (url.pathname === "/client/v4/__stats")
    return reply(200, { posts, writes, records: rows.length, rows, reads });
  if (req.method === "GET" && url.pathname === "/client/v4/zones") {
    return reply(
      200,
      url.searchParams.get("name") === "example.com"
        ? [{ id: zone, name: "example.com" }]
        : [],
    );
  }
  if (url.pathname.startsWith(`/client/v4/zones/${zone}/dns_records`) && req.method !== "GET") writes++;
  if (url.pathname === `/client/v4/zones/${zone}/dns_records`) {
    if (req.method === "GET") {
      const name = url.searchParams.get("name");
      if (!name) return reply(400, []);
      reads.push(name);
      if (mode === "wildcard-read-denied" && name.startsWith("*.")) return reply(403, []);
      if (mode === "wildcard-incomplete" && name.startsWith("*.")) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ success: true, result: [], result_info: { total_pages: 2 } }));
      }
      return reply(200, rows.filter((row) => row.name === name));
    }
    if (req.method === "POST") {
      posts++;
      if (mode === "denied") return reply(403, []);
      let body = req.body;
      if (!body) {
        let text = "";
        for await (const chunk of req) text += chunk;
        try {
          body = JSON.parse(text);
        } catch {
          return reply(400, []);
        }
      }
      if (typeof body === "string") {
        try {
          body = JSON.parse(body);
        } catch {
          return reply(400, []);
        }
      }
      if (
        !["A", "AAAA"].includes(body.type) ||
        body.name !== (mode.startsWith("nested") ? "admin.sub.example.com" : "admin.example.com") ||
        body.proxied !== true ||
        body.ttl !== 1 ||
        typeof body.comment !== "string"
      )
        return reply(400, []);
      if (rows.some((row) => row.name === body.name && row.type === body.type)) return reply(400, []);
      if (mode === "unknown-uncommitted") return reply(500, []);
      const row = { ...body, id };
      rows.push(row);
      if (mode === "unknown-committed") return reply(500, []);
      return reply(200, row);
    }
  }
  reply(501, []);
});
server.listen(process.env.PORT);
