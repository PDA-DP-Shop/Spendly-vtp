const $=id=>document.getElementById(id);
const canvas=$("vtpCanvas"),ctx=canvas.getContext("2d",{willReadFrequently:true});
const video=$("video"),scanCanvas=$("scanCanvas"),scanCtx=scanCanvas.getContext("2d",{willReadFrequently:true});
const N=48;let stream=null,scanTimer=null,attempts=0,busy=false,lastSuccess=0;

const utf8=s=>new TextEncoder().encode(s);
const fromUtf8=a=>new TextDecoder().decode(a);
function crc32(bytes){let c=0xffffffff;for(const b of bytes){c^=b;for(let k=0;k<8;k++)c=(c>>>1)^(0xedb88320&-(c&1))}return(c^0xffffffff)>>>0}
async function key(secret){const b=await crypto.subtle.importKey("raw",utf8(secret),"PBKDF2",false,["deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt:utf8("SPENDLY-VTP-V0-2"),iterations:100000,hash:"SHA-256"},b,{name:"AES-GCM",length:256},false,["encrypt","decrypt"])}
async function encrypt(t){const k=await key("SPENDLY-VTP-DEMO-KEY");const iv=crypto.getRandomValues(new Uint8Array(12));const ct=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},k,utf8(t)));return new Uint8Array([...iv,...ct])}
async function decrypt(a){const k=await key("SPENDLY-VTP-DEMO-KEY");return fromUtf8(new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:a.slice(0,12)},k,a.slice(12)))}

function bits(bytes){const out=[];for(const b of bytes)for(let i=7;i>=0;i--)out.push((b>>i)&1);return out}
function anchor(x,y,s){ctx.fillStyle="#000";ctx.fillRect(x,y,s,s);ctx.fillStyle="#fff";ctx.fillRect(x+s*.18,y+s*.18,s*.64,s*.64);ctx.fillStyle="#000";ctx.fillRect(x+s*.36,y+s*.36,s*.28,s*.28)}
function reserved(r,c){return(r>=3&&r<8&&c>=3&&c<8)||(r>=3&&r<8&&c>=N-8&&c<N-3)||(r>=N-8&&r<N-3&&c>=3&&c<8)||(r>=N-8&&r<N-3&&c>=N-8&&c<N-3)}
function render(bytes){
ctx.fillStyle="#fff";ctx.fillRect(0,0,canvas.width,canvas.height);const cell=canvas.width/N,s=cell*5;
ctx.strokeStyle="#000";ctx.lineWidth=cell;ctx.strokeRect(cell*2,cell*2,cell*(N-4),cell*(N-4));
anchor(cell*3,cell*3,s);anchor(canvas.width-cell*8,cell*3,s);anchor(cell*3,canvas.height-cell*8,s);anchor(canvas.width-cell*8,canvas.height-cell*8,s);
const h=new Uint8Array(11);h.set([86,84,80,49]);h[4]=(bytes.length>>>8)&255;h[5]=bytes.length&255;const c=crc32(bytes);h[6]=c>>>24;h[7]=c>>>16;h[8]=c>>>8;h[9]=c;h[10]=1;
const all=new Uint8Array(h.length+bytes.length);all.set(h);all.set(bytes,11);const bs=bits(all);let i=0;
for(let r=2;r<N-2;r++)for(let c2=2;c2<N-2;c2++){if(reserved(r,c2)||i>=bs.length)continue;ctx.fillStyle=bs[i++]?"#000":"#fff";ctx.fillRect(c2*cell,r*cell,cell+.2,cell+.2)}
}

async function generate(){
const obj={protocol:"VTP",version:1,type:"BILL",shopId:$("shopId").value,invoiceId:$("invoiceId").value,total:Number($("total").value||0),currency:"INR",note:$("note").value,createdAt:new Date().toISOString()};
const raw=utf8(JSON.stringify(obj)),enc=await encrypt(JSON.stringify(obj)),p=new Uint8Array(enc.length+4);p.set(enc);const c=crc32(raw);p[p.length-4]=c>>>24;p[p.length-3]=c>>>16;p[p.length-2]=c>>>8;p[p.length-1]=c;render(p);$("status").textContent=`Generated VTP packet: ${p.length} bytes.`}
function sample(){
const w=scanCanvas.width,h=scanCanvas.height,side=Math.min(w,h)*.8,ox=(w-side)/2,oy=(h-side)/2,cell=side/N,img=scanCtx.getImageData(ox,oy,Math.floor(side),Math.floor(side)).data;
const g=(r,g,b)=>.299*r+.587*g+.114*b;const bit=(r,c)=>{const x=Math.floor((c+.5)*cell),y=Math.floor((r+.5)*cell);let s=0,n=0;for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++){const xx=Math.max(0,Math.min(Math.floor(side)-1,x+dx)),yy=Math.max(0,Math.min(Math.floor(side)-1,y+dy)),p=(yy*Math.floor(side)+xx)*4;s+=g(img[p],img[p+1],img[p+2]);n++}return s/n<128?1:0};
const bs=[];for(let r=2;r<N-2;r++)for(let c=2;c<N-2;c++)if(!reserved(r,c))bs.push(bit(r,c));
const out=[];for(let i=0;i+7<bs.length;i+=8){let b=0;for(let j=0;j<8;j++)b=(b<<1)|bs[i+j];out.push(b)}return new Uint8Array(out)}
async function scanOnce(){
if(busy||!stream||video.readyState<2)return;busy=true;attempts++;$("attempts").textContent=attempts;
scanCanvas.width=video.videoWidth;scanCanvas.height=video.videoHeight;scanCtx.drawImage(video,0,0,scanCanvas.width,scanCanvas.height);
const t=performance.now();
try{const b=sample();if(b[0]!==86||b[1]!==84||b[2]!==80||b[3]!==49)throw 0;const len=(b[4]<<8)|b[5];const p=b.slice(11,11+len);if(p.length!==len)throw 0;const enc=p.slice(0,-4);const stored=((p[p.length-4]<<24)|(p[p.length-3]<<16)|(p[p.length-2]<<8)|p[p.length-1])>>>0;const plain=await decrypt(enc);const actual=crc32(utf8(plain));const obj=JSON.parse(plain);$("result").textContent=JSON.stringify({protocol:"VTP",verified:stored===actual,transaction:obj},null,2);$("scanTime").textContent=(performance.now()-t).toFixed(1)+" ms";$("scanState").textContent="DECODED";$("decodeStatus").textContent="VTP detected automatically.";lastSuccess=Date.now()}catch(e){if(Date.now()-lastSuccess>800){$("scanState").textContent="SEARCHING";$("decodeStatus").textContent="Continuously scanning…"}}finally{busy=false}}
async function start(){try{stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:"environment"}},audio:false});video.srcObject=stream;await video.play();attempts=0;$("attempts").textContent=0;$("startCamera").disabled=true;$("stopCamera").disabled=false;$("scanState").textContent="SEARCHING";$("scanIndicator").textContent="AUTO SCAN ON";scanTimer=setInterval(scanOnce,120)}catch(e){$("decodeStatus").textContent="Camera error: "+e.message}}
function stop(){if(scanTimer)clearInterval(scanTimer);scanTimer=null;if(stream)stream.getTracks().forEach(t=>t.stop());stream=null;video.srcObject=null;$("startCamera").disabled=false;$("stopCamera").disabled=true;$("scanState").textContent="OFF";$("scanIndicator").textContent="SCANNER OFF";$("decodeStatus").textContent="Camera stopped."}
$("generate").onclick=generate;$("startCamera").onclick=start;$("stopCamera").onclick=stop;generate();
