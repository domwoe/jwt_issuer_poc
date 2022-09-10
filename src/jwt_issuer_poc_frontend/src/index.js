import { jwt_issuer_poc_backend } from "../../declarations/jwt_issuer_poc_backend";
import { verifyJWT, decodeJWT } from 'did-jwt';
import { Resolver } from 'did-resolver'
import key from 'key-did-resolver'
import { prettyPrintJson } from 'pretty-print-json';

const keyResolver = key.getResolver();
const resolver = new Resolver(keyResolver)


document.querySelector("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const button = e.target.querySelector("button");

  const kind = document.getElementById("token_kind").value;

  button.setAttribute("disabled", true);

  const key = await jwt_issuer_poc_backend.tecdsa_public_key("did_key");
  const res = await jwt_issuer_poc_backend.issue(kind);
  const jwt = res.Ok;

  console.log(jwt)

  button.removeAttribute("disabled");

  let decoded = decodeJWT(jwt)
  console.log(decoded)
  document.getElementById('decoded').innerHTML = prettyPrintJson.toHtml(decoded);

  if (kind == "tecdsa") {
    let verificationResponse = await verifyJWT(jwt, {
      resolver,
    })
    console.log(verificationResponse)

    const elem = document.getElementById('result');
    elem.innerHTML = prettyPrintJson.toHtml(verificationResponse);
  } else {

    if (kind == "iccsa") {
      let hash = decoded.signature
      const real_iccsa_sig = await jwt_issuer_poc_backend.get_iccsa(hash); 
      decoded.signature = real_iccsa_sig.Ok;
      const _ = await jwt_issuer_poc_backend.get_iccsa(hash); 
      document.getElementById('decoded').innerHTML = prettyPrintJson.toHtml(decoded);
    }
    
    const elem = document.getElementById('result');
    elem.innerHTML = "Verification not implemented for kind: " + kind;

  }

  return false;
});
