const http = require('http');
const crypto = require('crypto');
const url = require('url');

// 企业配置信息
const token = '';
const encodingAESKey = ''; // 43位字符
const corpId = 'your_corp_id';

// 创建HTTP服务
const server = http.createServer(async (req, res) => {
  try {
    // 解析URL参数
    const parsedUrl = url.parse(req.url, true);
    const { query } = parsedUrl;

    // 步骤1：URL解码（Node.js自动处理）
    // 步骤2：验证签名
    const signature = validateSignature(query);
    if (signature !== query.msg_signature) {
      res.statusCode = 403;
      return res.end('Invalid signature');
    }

    // 步骤3：解密消息
    const decryptedMsg = decryptEchostr(query.echostr);
    
    // 立即返回明文消息
    res.setHeader('Content-Type', 'text/plain');
    res.end(decryptedMsg);
  } catch (err) {
    res.statusCode = 500;
    res.end(err.message);
  }
});

// 验证签名函数
function validateSignature(queryParams) {
  const { timestamp, nonce, echostr } = queryParams;
  const sorted = [token, timestamp, nonce, echostr]
    .sort()
    .join('');
  return crypto
    .createHash('sha1')
    .update(sorted)
    .digest('hex');
}

// 解密函数
function decryptEchostr(encryptedStr) {
  // 处理AESKey
  const aesKey = Buffer.from(encodingAESKey + '=', 'base64');
  if (aesKey.length !== 32) {
    throw new Error('Invalid AES key length');
  }

  // 创建解密器
  const iv = aesKey.slice(0, 16);
  const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
  decipher.setAutoPadding(false);

  try {
    // 执行解密
    const encryptedBuffer = Buffer.from(encryptedStr, 'base64');
    let decrypted = Buffer.concat([
      decipher.update(encryptedBuffer),
      decipher.final()
    ]);

    // 处理PKCS#7填充
    const pad = decrypted[decrypted.length - 1];
    decrypted = decrypted.slice(0, decrypted.length - pad);

    // 解析消息结构
    const msgLength = decrypted.readUInt32BE(16);
    const msgStart = 20;
    const msgEnd = msgStart + msgLength;
    
    // 验证消息长度
    if (msgEnd > decrypted.length) {
      throw new Error('Invalid message length');
    }

    // 提取消息内容
    const message = decrypted.slice(msgStart, msgEnd);
    const receiveId = decrypted.slice(msgEnd).toString();

    // 验证企业ID
    if (receiveId !== corpId) {
      throw new Error('CorpID mismatch');
    }

    return message.toString();
  } catch (err) {
    throw new Error(`Decryption failed: ${err.message}`);
  }
}

// 启动服务
server.listen(8089, () => {
  console.log('Server running on port 8089');
});
