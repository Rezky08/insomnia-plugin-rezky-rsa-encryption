const JSEncrypt = require("node-rsa")
const CryptoJS = require("crypto-js")
const jp = require('jsonpath-plus');
let chainToResponseObject = {}


const generateSignature = (signatureKey, uuid, values) => {
    console.log("- Raw signature key: " + signatureKey);
    let signature = signatureKey + "#" + uuid + "#";
    for (let valueIndex in values) {
        let value = values[valueIndex]??"";
        signature = signature + value + "#";
    }

    console.log("- Raw signature: " + signature);

    let hashSignature = CryptoJS.SHA256(signature).toString();
    console.log("- Hash signature: " + hashSignature);

    return hashSignature;
};
const getContextSearch = async (context) => {
    const {meta} = context;

    if (!meta.requestId || !meta.workspaceId) {
        return null;
    }

    const request = await context.util.models.request.getById(meta.requestId);
    const workspace = await context.util.models.workspace.getById(meta.workspaceId);

    if (!request) {
        throw new Error(`Request not found for ${meta.requestId}`);
    }

    if (!workspace) {
        throw new Error(`Workspace not found for ${meta.workspaceId}`);
    }

    return {
        body: JSON.parse(request.body.text),
        headers: request.headers,
        parameters: request.parameters
    }
}
const decrypt = (encryptedText, private_key) => {
    var crypt = new JSEncrypt(private_key);
    crypt.setOptions({encryptionScheme: 'pkcs1'});
    return crypt.decrypt(encryptedText, 'utf8')
}
const encrypt = (textToEncrypt, public_key) => {
    var crypt = new JSEncrypt(public_key);
    crypt.setOptions({encryptionScheme: 'pkcs1'});
    return crypt.encrypt(textToEncrypt, 'base64')
}
const handlerMap = {
    "encrypt": (ctx, params) => {
        const request = ctx.request
        const textToEncrypt = params[0]
        if (!textToEncrypt) {
            throw new Error("encrypt function need text to encrypt");
        }
        const public_key = request.getEnvironmentVariable("public_key")
        return encrypt(textToEncrypt, public_key)
    },
    "decrypt": (ctx, params) => {
        const request = ctx.request
        const textToDecrypt = params[0]
        if (!textToDecrypt) {
            throw new Error("encrypt function need text to encrypt");
        }
        const private_key = request.getEnvironmentVariable("private_key")
        return decrypt(textToDecrypt, private_key)
    },
    "cookie": (ctx, params) => {
        const request = ctx.request
        const cookieName = params[0]
        if (!cookieName) {
            throw new Error("cookie must have a name");
        }
        const cookieValue = params[1]
        if (!cookieValue) {
            throw new Error("cookie must have value");
        }
        request.setCookie(cookieName, cookieValue)
        return cookieValue
    },
    "bindResponse" : (ctx, params) => {
        const request = ctx.request
        const responseFieldName = params[0]
        if (!responseFieldName) {
            throw new Error("bind response must filled name");
        }
        const responseFieldValue = params[1]
        if (!responseFieldValue) {
            throw new Error("response field must have value");
        }
        chainToResponseObject[responseFieldName] = responseFieldValue
        return responseFieldValue
    },
    "split" : (ctx, params) => {
        let textToSplit = params[0]
        const separator = params[1]
        const filter = params[2]
        if (typeof textToSplit !== "string"){
            textToSplit = textToSplit.toString()
        }
        let result = textToSplit.split(separator)
        if (!!filter){
            result = jp.JSONPath({path:filter,json:result})
        }
        return result
    },
}

function replaceInnermostValue(ctx, input, replacer) {
    while (true) {
        const match = input?.match(/(\[\%[^\[\]]+\%\])/);

        if (!match) {
            break;
        }

        const nestedString = match[1];
        const replacement = replacer(ctx, nestedString)
        input = input.replace(nestedString, replacement);
    }

    return input;
}

const execHandlerFunc = (ctx, inputString) => {
    let pattern = new RegExp(`^\\[\\%(.+?)\\:(.*?)\\%\\]$`, 'g')
    let match = [...inputString.matchAll(pattern)][0]??[];
    if (match.length === 0){
        return ""
    }
    const keyword = match[1]
    const params = match[2]??""
    const handler = handlerMap[keyword]
    if (!handler) {
        throw new Error(`keyword '${keyword}' is notfound`)
    }
    return execHandlerParams(ctx, keyword, handler, params)
}


const execHandlerParams = (ctx, keyword, handler, plainParams) => {
    if (typeof plainParams === "object") {
        plainParams = JSON.stringify(plainParams)
    }
    let params = plainParams.split(",")
    return handler(ctx, params)
}

const bufferToJsonObj = buf => JSON.parse(buf.toString('utf-8'));
const jsonObjToBuffer = obj => Buffer.from(JSON.stringify(obj), 'utf-8');

module.exports.templateTags = [
    {
        name: 'decrypt',
        displayName: 'Decrypt',
        description: 'Decrypt text using private key',
        args: [
            {
                displayName: 'Encrypted Text',
                type: 'string',
                defaultValue: '',
            },
            {
                displayName: 'Private Key',
                type: 'string',
                defaultValue: '',
            },
        ],
        async run(context, encryptedText, private_key) {
            return decrypt(encryptedText, private_key);
        },
    },
    {
        name: 'encrypt',
        displayName: 'Encrypt',
        description: 'Encrypt text using public key',
        args: [
            {
                displayName: 'Text to Encrypt',
                type: 'string',
                defaultValue: '',
            },
            {
                displayName: 'Public Key',
                type: 'string',
                defaultValue: '',
            },
        ],
        async run(context, textToEncrypt, public_key) {
            return encrypt(textToEncrypt, public_key);
        },
    },
    {
        name: 'getBodyJsonPath',
        displayName: 'Get Body Json Path',
        description: 'Custom tag to extract value from JSON using XPath',
        args: [
            {
                displayName: 'JSON XPath',
                type: 'string',
            },
        ],
        async run(context, jsonXPath) {
            const {meta} = context;

            if (!meta.requestId || !meta.workspaceId) {
                return null;
            }

            const request = await context.util.models.request.getById(meta.requestId);
            const workspace = await context.util.models.workspace.getById(meta.workspaceId);

            if (!request) {
                throw new Error(`Request not found for ${meta.requestId}`);
            }

            if (!workspace) {
                throw new Error(`Workspace not found for ${meta.workspaceId}`);
            }

            const requestBody = request.body.text;
            if (!requestBody) {
                return 'Request body is empty!';
            }

            try {
                let jsonBody = JSON.parse(requestBody)
                return jp.JSONPath({path: jsonXPath, json: jsonBody})
            } catch (error) {
                return 'Error extracting value: ' + error.message;
            }
        },
    },
    {
        name: 'substringTag',
        displayName: 'Substring Tag',
        description: 'Custom tag to perform substring operation on a given string',
        args: [
            {
                displayName: 'String',
                type: 'string',
            },
            {
                displayName: 'Start Index',
                type: 'number',
            },
            {
                displayName: 'Length',
                type: 'number',
            },
        ],
        async run(context, inputString, startIndex, length) {
            let result = null
            try {
                const jsonSearch = await getContextSearch(context)
                result = jp.JSONPath({path: inputString, json: jsonSearch})

                if (result.length === 1 && typeof result[0] != "object") {
                    result = result[0]
                }


                if (typeof result == "object" && result.length > 0) {
                    return 'Error "' + inputString + '" is Not String\n' + JSON.stringify(result)
                }

                if (!!result && typeof result == "string") {
                    // Perform substring operation
                    return result.substring(startIndex, startIndex + length);
                }
            } catch (error) {
            }

            if (!inputString) {
                return 'Input string is empty!';
            }

            try {
                // Perform substring operation
                return inputString.substring(startIndex, startIndex + length);
            } catch (error) {
                return 'Error performing substring: ' + error.message;
            }
        },
    },
    {
        name: 'signature1',
        displayName: 'Signature 1 (With UUID Reverse)',
        description: 'Use first 10 char of UUID and reverse it as Signature Key',
        args: [
            {
                displayName: 'String',
                type: 'string',
            },
            {
                displayName: 'Start Index',
                type: 'number',
            },
            {
                displayName: 'Length',
                type: 'number',
            },
        ],
        async run(context, inputString, startIndex, length) {
            let result = null
            try {
                const jsonSearch = await getContextSearch(context)
                result = jp.JSONPath({path: inputString, json: jsonSearch})

                if (result.length === 1 && typeof result[0] != "object") {
                    result = result[0]
                }


                if (typeof result == "object" && result.length > 0) {
                    return 'Error "' + inputString + '" is Not String\n' + JSON.stringify(result)
                }

                if (!!result && typeof result == "string") {
                    // Perform substring operation
                    return result.substring(startIndex, startIndex + length);
                }
            } catch (error) {
            }

            if (!inputString) {
                return 'Input string is empty!';
            }

            try {
                // Perform substring operation
                return inputString.substring(startIndex, startIndex + length);
            } catch (error) {
                return 'Error performing substring: ' + error.message;
            }
        },
    },
];
module.exports.requestHooks = [
    context => {
        chainToResponseObject = {}
        try {
            const signatureFlagKey = 'SIGNATURE-FLAG'
            const request = context.request
            let bodyText = request.getBody().text
            bodyText = replaceInnermostValue(context, bodyText, execHandlerFunc)

            let body = JSON.parse(bodyText)

            const signatureFlag = request.getHeader(signatureFlagKey)
            if (!!signatureFlag){
                // Pisahkan string menjadi array berdasarkan tanda koma
                const dataArray = signatureFlag.split(',');
                if (dataArray.length > 1) {
                    // Ekstrak data dari array
                    const signatureType = dataArray[0].split(':')[1];
                    const signatureHeaderName = dataArray[1];
                    const uuidField = dataArray[2];
                    const combineFields = dataArray.slice(3);


                    let signatureHash = ""
                    let uuid = request.getHeader(uuidField)
                    let signatureKey = ""
                    let fields = []

                    switch (parseInt(signatureType)) {
                        case 1:
                            signatureKey = uuid.substring(0, 10)
                            signatureKey = signatureKey.split("")?.reverse()?.join("")
                            break
                        case 2:
                            signatureKey = request.getEnvironmentVariable("signature_key")
                            break
                    }

                    combineFields.forEach(function (value) {
                        fields.push(eval("body." + value))
                    })
                    signatureHash = generateSignature(signatureKey, uuid, fields)

                    request.addHeader(signatureHeaderName, signatureHash)
                    request.removeHeader(signatureFlagKey)
                }

            }
            context.request.setBody({
                ...request.getBody(),
                text: JSON.stringify(body),
            });

        } catch (e) {
            console.error(e)
            throw new Error(e)
        }
    },
]
module.exports.responseHooks = [
    async context => {
        try {
            const resp = bufferToJsonObj(context.response.getBody());
            if (Object.keys(chainToResponseObject).length>0){
                // Modify
                resp.__request = chainToResponseObject;
            }
            context.response.setBody(jsonObjToBuffer(resp));
        } catch {
            // no-op
        }
    }
]
