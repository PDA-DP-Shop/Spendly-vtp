const $ = id => document.getElementById(id);
const canvas = $("vtpCanvas");
const ctx = canvas.getContext("2d", {willReadFrequently:true});
const video = $("video");
const scanCanvas = $("scanCanvas");
const scanCtx = scanCanvas.getContext("2d", {willReadFrequently:true});
let stream = null;
let lastPayload = null;

const N = 48;
const PAD = 4;

function utf8(s){ return new TextEncoder().encode(s); }
function fromUtf8(a){ return new TextDecoder().decode(a); }

function crc32(bytes){
  let c = 0xffffffff;
  for(const b of bytes){
    c ^= b;
    for(let k=0;k<8;k++) c = (c>>>1) ^ (0xedb88320 & -(c&1));
  }
  return (c ^ 0xffffffff) >>> 0;
}

async function deriveKey(secret){
  const base = await crypto.subtle.importKey("raw", utf8(secret), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {name:"PBKDF2",salt:utf8("SPENDLY-VTP-V0-1"),iterations:100000,hash:"SHA-256"},
    base,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]
  );
}

async function encrypt(text, secret){
  const key = await deriveKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},key,utf8(text)));
  return new Uint8Array([...iv,...ct]);
}

async function decrypt(bytes, secret){
  const key = await deriveKey(secret);
  const iv = bytes.slice(0,12), ct = bytes.slice(12);
  const plain = await crypto.subtle.decrypt({name:"AES-GCM",iv},key,ct);
  return fromUtf8(new Uint8Array(plain));
}

function buildBits(bytes){
  const bits=[];
  for(const b of bytes) for(let i=7;i>=0;i--) bits.push((b>>i)&1);
  return bits;
}

function drawAnchor(x,y,size){
  ctx.fillStyle="#000"; ctx.fillRect(x,y,size,size);
  ctx.fillStyle="#fff"; ctx.fillRect(x+size*.18,y+size*.18,size*.64,size*.64);
  ctx.fillStyle="#000"; ctx.fillRect(x+size*.36,y+size*.36,size*.28,size*.28);
}

function renderVTP(bytes){
  ctx.fillStyle="#fff"; ctx.fillRect(0,0,canvas.width,canvas.height);
  const cell = canvas.width/N;
  // border
  ctx.strokeStyle="#000"; ctx.lineWidth=cell;
  ctx.strokeRect(cell*2,cell*2,cell*(N-4),cell*(N-4));

  // four anchors
  const s=cell*5;
  drawAnchor(cell*3,cell*3,s);
  drawAnchor(canvas.width-cell*8,cell*3,s);
  drawAnchor(cell*3,canvas.height-cell*8,s);
  drawAnchor(canvas.width-cell*8,canvas.height-cell*8,s);

  // metadata stripe: VTP1 + payload length + CRC
  const header = new Uint8Array(11);
  header.set([0x56,0x54,0x50,0x31],0);
  const len=bytes.length;
  header[4]=(len>>>8)&255; header[5]=len&255;
  const c=crc32(bytes);
  header[6]=(c>>>24)&255; header[7]=(c>>>16)&255; header[8]=(c>>>8)&255; header[9]=c&255;
  header[10]=0x01;

  const all = new Uint8Array(header.length+bytes.length);
  all.set(header); all.set(bytes,header.length);
  const bits=buildBits(all);

  // data region: 36x36 cells excluding 4 anchor blocks
  let bi=0;
  const reserved=(r,c)=>{
    return (r>=3&&r<8&&c>=3&&c<8) ||
           (r>=3&&r<8&&c>=N-8&&c<N-3) ||
           (r>=N-8&&r<N-3&&c>=3&&c<8) ||
           (r>=N-8&&r<N-3&&c>=N-8&&c<N-3);
  };
  for(let r=2;r<N-2;r++){
    for(let c2=2;c2<N-2;c2++){
      if(reserved(r,c2)) continue;
      if(bi>=bits.length) break;
      const on=bits[bi++];
      ctx.fillStyle=on?"#000":"#fff";
      ctx.fillRect(c2*cell,r*cell,cell+0.2,cell+0.2);
    }
  }

  // timing / identity marks
  ctx.fillStyle="#000";
  for(let i=10;i<N-10;i+=2){
    ctx.fillRect(i*cell,(N/2-1)*cell,cell,cell);
  }
}

function pack(obj){
  const json=JSON.stringify(obj);
  return utf8(json);
}

async function generate(){
  const obj={
    protocol:"VTP",
    version:1,
    type:"BILL",
    shopId:$("shopId").value.trim(),
    invoiceId:$("invoiceId").value.trim(),
    total:Number($("total").value||0),
    currency:"INR",
    note:$("note").value,
    createdAt:new Date().toISOString()
  };
  try{
    // Demo secret. In a production design this MUST be replaced by a real key exchange.
    const encrypted=await encrypt(JSON.stringify(obj),"SPENDLY-VTP-DEMO-KEY");
    const payload=new Uint8Array(encrypted.length+4);
    const raw=pack(obj);
    const check=crc32(raw);
    payload.set(encrypted,0);
    payload[payload.length-4]=(check>>>24)&255;
    payload[payload.length-3]=(check>>>16)&255;
    payload[payload.length-2]=(check>>>8)&255;
    payload[payload.length-1]=check&255;
    lastPayload=payload;
    renderVTP(payload);
    $("status").textContent=`Generated VTP packet: ${payload.length} bytes encrypted payload.`;
  }catch(e){
    $("status").textContent="Generation failed: "+e.message;
  }
}

function readBitsFromGuide(){
  // Guided v0.1 decoder: assumes the code is centered inside the scanner guide.
  const w=scanCanvas.width,h=scanCanvas.height;
  const side=Math.min(w,h)*0.8;
  const ox=(w-side)/2, oy=(h-side)/2;
  const cell=side/N;
  const img=scanCtx.getImageData(ox,oy,side,side).data;

  function gray(r,g,b){return .299*r+.587*g+.114*b;}
  function sampleCell(r,c){
    const x=Math.floor((c+.5)*cell), y=Math.floor((r+.5)*cell);
    let sum=0,count=0;
    for(let dy=-2;dy<=2;dy++) for(let dx=-2;dx<=2;dx++){
      const xx=Math.min(side-1,Math.max(0,x+dx)), yy=Math.min(side-1,Math.max(0,y+dy));
      const p=(yy*Math.floor(side)+xx)*4;
      sum+=gray(img[p],img[p+1],img[p+2]); count++;
    }
    return sum/count<128?1:0;
  }

  const reserved=(r,c)=>{
    return (r>=3&&r<8&&c>=3&&c<8) ||
           (r>=3&&r<8&&c>=N-8&&c<N-3) ||
           (r>=N-8&&r<N-3&&c>=3&&c<8) ||
           (r>=N-8&&r<N-3&&c>=N-8&&c<N-3);
  };
  const bits=[];
  for(let r=2;r<N-2;r++){
    for(let c=2;c<N-2;c++){
      if(reserved(r,c)) continue;
      bits.push(sampleCell(r,c));
    }
  }
  const bytes=[];
  for(let i=0;i+7<bits.length;i+=8){
    let b=0; for(let j=0;j<8;j++) b=(b<<1)|bits[i+j];
    bytes.push(b);
  }
  return new Uint8Array(bytes);
}

async function decodeCapture(){
  if(!stream){$("decodeStatus").textContent="Start the camera first.";return;}
  scanCanvas.width=video.videoWidth||720; scanCanvas.height=video.videoHeight||720;
  scanCtx.drawImage(video,0,0,scanCanvas.width,scanCanvas.height);
  try{
    const bytes=readBitsFromGuide();
    if(bytes[0]!==0x56||bytes[1]!==0x54||bytes[2]!==0x50||bytes[3]!==0x31) throw new Error("VTP header not detected. Align the code inside the guide.");
    const len=(bytes[4]<<8)|bytes[5];
    const expected=((bytes[6]<<24)|(bytes[7]<<16)|(bytes[8]<<8)|bytes[9])>>>0;
    const payload=bytes.slice(11,11+len);
    if(payload.length!==len) throw new Error("Incomplete payload.");
    const encrypted=payload.slice(0,-4);
    const stored=((payload[payload.length-4]<<24)|(payload[payload.length-3]<<16)|(payload[payload.length-2]<<8)|payload[payload.length-1])>>>0;
    const plain=await decrypt(encrypted,"SPENDLY-VTP-DEMO-KEY");
    const obj=JSON.parse(plain);
    const actual=crc32(utf8(plain));
    $("result").textContent=JSON.stringify({
      protocol:"VTP",
      verified: stored===actual,
      transaction:obj
    },null,2);
    $("decodeStatus").textContent="VTP decoded successfully.";
  }catch(e){
    $("decodeStatus").textContent=e.message;
  }
}

async function startCamera(){
  try{
    stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:"environment"}},audio:false});
    video.srcObject=stream;
    await video.play();
    $("capture").disabled=false; $("stopCamera").disabled=false;
    $("decodeStatus").textContent="Camera active. Align the VTP code with the guide.";
  }catch(e){
    $("decodeStatus").textContent="Camera permission/error: "+e.message;
  }
}
function stopCamera(){
  if(stream){stream.getTracks().forEach(t=>t.stop());stream=null;}
  video.srcObject=null; $("capture").disabled=true; $("stopCamera").disabled=true;
  $("decodeStatus").textContent="Camera stopped.";
}

$("generate").onclick=generate;
$("startCamera").onclick=startCamera;
$("stopCamera").onclick=stopCamera;
$("capture").onclick=decodeCapture;
generate();
