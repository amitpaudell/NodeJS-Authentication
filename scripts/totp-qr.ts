import QRCode from 'qrcode'

const optAuthUrl=process.argv[2];

if(!optAuthUrl){
  throw new Error('PassOTP AUTH URL as argument')
}

async function main() {
  await QRCode.toFile('totp.png',optAuthUrl);
  console.log('Save QR Code')
}

main().catch(err=>{
  console.error(err);
  process.exit(1);
})

