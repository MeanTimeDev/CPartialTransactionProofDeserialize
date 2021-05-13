//test decode partial transaction proof
const varint = require('varint');
const blake2b = require ('./blake2b/index.js');
const BLAKE2B = "blake2b";
/* BLAKE2B key */
const BLAKE2BKEY = "VerusDefaultHash";

function blake2BHash(obj1,obj2 = null){

    let out = Buffer.allocUnsafe(32); 
    let personal = Buffer.from(BLAKE2BKEY);
    let hash = blake2b(out.length, null, null, personal);
    hash = hash.update(obj1);
    if(obj2) hash = hash.update(obj2);
    return hash.digest(out);           
}

//const input = "0102030000000202010201912705cc0d8be06668c60e68bae19b76b18bb84c7fd799534fae4a607b94a206020200020188c4dea916716c0a636fdaeea5c1ac3668390834be6c65779465d4c82f0100000303e45b809347234e52af000000000000000000000000000000000000000000000000000000000006f42a49a17ff57464f2081f6dca7dece0800897b34be01169f5c6786aaba5807e2a52010000000000000000000000000000000000000000000000000000000073a70b4d3459c1ae65088ea808b84bd3e36019681dffce651d2c80cbcdeb48d34c137802000000000000000000000000000000000000000000000000000000004d8f418ac459d7060dad5945bc3912a9eb184915c8499f834780ac43226a6dc3b005bd05000000000000000000000000000000000000000000000000000000006f7be747335a8a9b5708d184d6d53d281a6f6ee2d6de7e8cacc8c0e0dd0a650043251b09000000000000000000000000000000000000000000000000000000001e5d47136cc7226813a10e65e6f4340b758452cd0046f32633f0ec4de714b85528a0620f0000000000000000000000000000000000000000000000000000000030de24df30f2248bde420c53d6dfc39e0bf3de29ec02fadc775bd7611baef6103be1232800000000000000000000000000000000000000000000000000000000c3e1fd0884c0f38d4a909bc58468d4861d5db2e95d4289d5c8d6883d3771e806c77d4d3200000000000000000000000000000000000000000000000000000000260cb861a0cb1e2df0f2efc779042b5fa6b94db1cd751724103591567ac1e8fc055e768b00000000000000000000000000000000000000000000000000000000b3053f530b3472844c790d26334e7cadc181f70f48cd5f6cff4a9ebede7109e72322dc7f01000000000000000000000000000000000000000000000000000000b93b8207bf390f8207d6dfb127045a20329d96b014cde765c35992aa84c64e0fc2c1292a0300000000000000000000000000000000000000000000000000000010069d84be09e936ec980cd481b4bb0ba3c292268bd599444d718ba313c2c88595faeec906000000000000000000000000000000000000000000000000000000a87dd1c666cdbe37df7e5682f983a4cd51a5deca1c6fbf44ee0e366d4d983007c756eee50d000000000000000000000000000000000000000000000000000000748fd379af677beba53fee7863aec6b0d867e04759868c20fe842e98e9c750a6ccb36b0c1c000000000000000000000000000000000000000000000000000000df11d5387010b86c3ba4d10500b461c63be79315b1b6444374d2f864866d009143c46e473800000000000000000000000000000000000000000000000000000036509004c7f48c781d4531977108bb9733341746e32a8bf0f59b9f543bbb57b841080ce33e000000000000000000000000000000000000000000000000000000074b12f0b19d60dcc665ae279a4542a340f4e9a7e3b1bd467459051d6d8234f27e92dfa4400000000000000000000000000000000000000000000000000000002d39b8cb2c77886a6362aabd99798322519d83810c6571358f60fd4dee82a4179937cca740000000000000000000000000000000000000000000000000000000030100000049dacf552eb2a01a5cb74055b45f813d9df00b03c0cb22ce02ff0c1501d9040ec2010400000085202f890100000003000000000000000000000000000000ef320000000000000000000001000000020200060384f31c3a347c9b0208a043267b5f3ca72e57c6f5f45a54932c51b4c3503301b5a4f0aa46c459f15a13165179bf8bebe109a64b844b0cfb60bdb0f5b0830519f3474bbebcea9905ddbef20c23c3dcae350a6c0cfb563b19739f07669039e2d90702005733000000000004000000fd03010000000000000000fa1a04030001011452047d0db35c330271aae70bedce996b5239ca5ccc4cdb04030c01011452047d0db35c330271aae70bedce996b5239ca5c4cbf01000300a6ef9ea235635e328124ff3429db9f9e91b64e2de453e45967460c2f56774ed27eeb8685f29f6cec0b090b0067460c2f56774ed27eeb8685f29f6cec0b090b0000000000000001a6ef9ea235635e328124ff3429db9f9e91b64e2d00e40b540200000001a6ef9ea235635e328124ff3429db9f9e91b64e2d00e40b54020000000000000000000000000000000000000000000000000000000000000000000000021473c4bdc43923729245a1bd8fe7e3c763f376bb46020000000075010000000202030603314f890f4d4bb963440c32e4b4fd8fa86d7b620a86c797ce547fb13d30f7b57a103c459d1ecedc87034c694677689106ef62662281b3cb1cfd217cffaf7ff24c474bbebcea9905ddbef20c23c3dcae350a6c0cfb563b19739f07669039e2d907";
const input = "01020300000002020102010b979e60a804b49ffe59c83620a4998f03bef198215262184d245da85991ae260202000201e4e7d8a9005e42029f76fb4d0ccc9a632b190983a741915590d6131fc3000000030380728074071ab9df0000000000000000000000000000000000000000000000000000000000855a19f394a9012d14281b5c6a1c09a7f56c91a471c22882318c89fbdc1c31ccd548c801000000000000000000000000000000000000000000000000000000007b0e7a6e4693ee50e470fd0b513271770f29c520a8801494b2f1e9d2a46f96d456196f0300000000000000000000000000000000000000000000000000000000d43dc14ca2db78cb623ff2899db367bc42e915fca4356299bd99ccfb98f700641b1e2c3500000000000000000000000000000000000000000000000000000000030100000049c131e3e333b905932309dbc2125f1d2e01898279efb26b6d6b197243f632a24a010400000085202f890400000004000000000000000000000000000000060100000000000000000000010000000202000d05f83a53ab52efb0387ff8ff7e518750bdd2029e5529096010977ac6ecfbe6c896f898c591c02f3cec905aad6076d7d209773c786de8404d035622673ef269b81e2f954ba268326f76e4538cee95f4f4a0a51f57bb31cf2bdead5fecbedcd6446c74d744f54a082be740cd5167e4aa31481ee292a5c4ca0aba080d3a6fba31835be408a98d46bf75240d71c4876aa2c406e56784ab216e5a040c380178309011ce02000100297ad36b500299be7a63de470332a3a4ab85a0add344bf09146cdb9160bb9e764b0400000000ffffffff010000000202020d0588bc611802613bc8f6faa0f678f3798a1f9379a80664222e07622b82accbd711195a0edca86775afd5ec76bfb0e06f56c32e0de1e13ca2606562358eb4e14adc2f954ba268326f76e4538cee95f4f4a0a51f57bb31cf2bdead5fecbedcd6446c74d744f54a082be740cd5167e4aa31481ee292a5c4ca0aba080d3a6fba31835be408a98d46bf75240d71c4876aa2c406e56784ab216e5a040c380178309011ce04000100fd40010000000000000000fd35011a04030001011452047d0db35c330271aae70bedce996b5239ca5ccc4d150104030c01011452047d0db35c330271aae70bedce996b5239ca5c4cf901000100a6ef9ea235635e328124ff3429db9f9e91b64e2d807080711b58ef611f87462e16715919bb0765d7cb59d0a608ecedeab7b3e19a6b50d557e7b1017284d47b760100000001a6ef9ea235635e328124ff3429db9f9e91b64e2deee89e3b0000000001a6ef9ea235635e328124ff3429db9f9e91b64e2deee89e3b0000000001a6ef9ea235635e328124ff3429db9f9e91b64e2dee1e04000000000001a6ef9ea235635e328124ff3429db9f9e91b64e2dee1e040000000000daf0f62234d4f6a82ee630bd8e9a165c64c5d7c58c39cd726a41b001381e297100000214d20c5312acde0af8350d4b0e8b76e8d9e3addc070200000000750100000002020a0d04f07467ff0b875cf4cb1aab2c6015252b0965a59d7f01de6a31c4aeac7a4de9612c86b1aed01e4ad283817bb42fd930885bac0d503ef119328a84cf19614bd5f4e893274acc1aa336ac64b8e107392e6609a99f4ac799343a7d83ecd6c6c452cce408a98d46bf75240d71c4876aa2c406e56784ab216e5a040c380178309011ce";
const notarization = {
    "version": 1,
    "notarizations": [
      {
        "index": 0,
        "txid": "c20e04d901150cff02ce22cbc0030bf09d3d815fb45540b75c1aa0b22e55cfda",
        "vout": 2,
        "notarization": {
          "version": 1,
          "prelaunch": true,
          "launchcleared": true,
          "launchconfirmed": true,
          "samechain": true,
          "proposer": {
            "type": 0,
            "nodestination": ""
          },
          "currencyid": "iCtawpxUiCc2sEupt7Z4u8SDAncGZpgSKm",
          "notarizationheight": 13017,
          "currencystate": {
            "flags": 24,
            "currencyid": "iCtawpxUiCc2sEupt7Z4u8SDAncGZpgSKm",
            "initialsupply": 0.00000000,
            "emitted": 0.00000000,
            "supply": 20000000.00000000,
            "currencies": {
              "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq": {
                "reservein": 0.00000000,
                "nativein": 0.00000000,
                "reserveout": 0.00000000,
                "lastconversionprice": 1.00000000,
                "viaconversionprice": 0.00000000,
                "fees": 100.00000000,
                "conversionfees": 0.00000000
              }
            },
            "nativefees": 0,
            "nativeconversionfees": 0,
            "nativeout": 2000000000000000,
            "preconvertedout": 0
          },
          "prevnotarizationhash": "65b0cf46ae794466ec50126eea1e13c6f6335cd46380ace4290f9015d0f399d6",
          "prevnotarizationout": 3,
          "hashprevnotarizationobject": "0000000000000000000000000000000000000000000000000000000000000000",
          "prevheight": 13003,
          "currencystates": [
          ],
          "proofroots": [
            {
              "version": 1,
              "type": 1,
              "systemid": "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq",
              "height": 13017,
              "stateroot": "35d3cd31e987fe3d7436e81606ab891c407ab4290c3cc53d2adce5150ad825df",
              "blockhash": "0000010542f78e28240dead88867cdc1bb67888c6611c790f79bc6ed26bf2b75",
              "power": "0000000000000000000000000000000000000000000000000000002c79ec0d2b"
            }
          ],
          "nodes": [
            {
              "networkaddress": "127.0.0.1:10000",
              "nodeidentity": "iLWvTJN5rUwm66SGmTnaPRm1onCZrfEUCt"
            }
          ]
        }
      }
    ],
    "forks": [
      [
        0
      ]
    ],
    "lastconfirmedheight": 13017,
    "lastconfirmed": 0,
    "bestchain": 0
  };
  
const BRANCH_TYPE =
    {
        BRANCH_INVALID : 0,
        BRANCH_BTC : 1,
        BRANCH_MMRBLAKE_NODE : 2,
        BRANCH_MMRBLAKE_POWERNODE : 3
    };

function deSerializePartialTransactionProof(input){

    let inputBuffer = Buffer.from(input,'hex');
    let pos = 0
    let decodedOutput = {};
    decodedOutput.version = inputBuffer.readInt8(pos);
    pos++;
    decodedOutput.type = inputBuffer.readInt8(pos);
    pos++;

    let proofSize = inputBuffer.readInt32LE(pos);
    pos +=4;
    //loop through the proof size
    decodedOutput.branches = [];

    for (let i = 0; i < proofSize; i++){
        
        let newBranch = parseBranch(inputBuffer.slice(pos));
        decodedOutput.branches.push(newBranch.branch);
        pos += newBranch.nBytes;
    }

 //   decodedOutput.branches = branches;
    let componentsSize = readCompactSize(inputBuffer.slice(pos));
    decodedOutput.components = [];
    pos += componentsSize.nBytes;
    for(let k = 0; k < componentsSize.size;k++){
        let component = {};
        component.elType = inputBuffer.readUInt16LE(pos);
        pos += 2;
        component.elIdx = inputBuffer.readUInt16LE(pos);
        pos += 2;
        //get size of array of bytes
        let elVchObjSize = readCompactSize(inputBuffer.slice(pos));
        pos += elVchObjSize.nBytes;
        component.elVchObj = inputBuffer.slice(pos,pos + (elVchObjSize.size));
        //get proofSize
        pos += elVchObjSize.size;
        
        let compProofSize = inputBuffer.readUInt32LE(pos);
        console.log(compProofSize);
        pos += 4;
        component.elProof = []; //CMMRProof an array of branches to be used as a proof sequence
        for(let l = 0;l < compProofSize; l++){
            //read a branch
            let newBranch = parseBranch(inputBuffer.slice(pos));
            component.elProof.push(newBranch.branch);
            pos += newBranch.nBytes;
        }
        decodedOutput.components.push(component);
    } 
    return decodedOutput;
}


function parseBranch(inputBuffer){
    let branchPos = 0;
    let branch = {};
    branch.branchType = inputBuffer.readUInt8(branchPos);
    branchPos++;
    if(branch.branchType == BRANCH_TYPE.BRANCH_MMRBLAKE_NODE || branch.branchType == BRANCH_TYPE.BRANCH_MMRBLAKE_NODE || branch.branchType == BRANCH_TYPE.BRANCH_MMRBLAKE_POWERNODE) {
        branch.branchType2 = inputBuffer.readUInt8(branchPos);
        branchPos++;
        branch.nIndex = ReadVarInt(inputBuffer.slice(branchPos));
        branchPos +=varint.encodingLength(branch.nIndex);
        branch.nSize = ReadVarInt(inputBuffer.slice(branchPos));
        branchPos +=varint.encodingLength(branch.nSize);
        let arraySize = readCompactSize(inputBuffer.slice(branchPos));
        branch.branch = [];
        //read an array of uint256/bytes32
        //read the compactSize of the vector
        branchPos += arraySize.nBytes;

        for(let j = 0; j < arraySize.size; j++){
                branch.branch.push(inputBuffer.slice(branchPos,(branchPos)+(32)).toString('hex'));
                branchPos+=32;
        }
    } else {
               console.log("Wrong branchtype",branch.branchType);
    } 
    //branches.push(branch);
    //console.log(branch);
    return {"branch" : branch,"nBytes": branchPos};
}


function readCompactSize(incomingBuffer){
    let pos = 0;
    let newBuffer = Buffer.from(incomingBuffer,'hex');
    let chSize = newBuffer.readUInt8();
    pos++;
    let returnSize = 0;
    let numBytes = 1;
    if(chSize < 253){
        returnSize = chSize;
    } else if(chSize == 253){
        returnSize = incomingBuffer.readUInt16LE(pos);
        numBytes += 2;
    } else if(chSize == 254){
        returnSize = incomingBuffer.readUInt32LE(pos);
        numBytes += 4;
    } else {
        returnSize = incomingBuffer.readBigUint64LE(pos);
        numBytes += 8;
    }
    return {"size": returnSize,"nBytes": numBytes};
}


function ReadVarInt(data){
    let n = 0;
    let is = Buffer.from(data,'hex');
    let pos = 0;
    while(true) {
        let chData = is.readUInt8(pos); //single char
        pos++;
        n = (n << 7) | (chData & 0x7F);
        if (chData & 0x80)
            n++;
        else
            return n;
    }
}

function WriteVarInt(newNumber){
    //let tmp = Array(Math.floor((sizeofInt(newNumber)*8+6)/7));
    let tmp = [];
    let len = 0;
    while(true){
        tmp[len] = (newNumber & 0x7f) | (len ? 0x80 : 0x00);
        if(newNumber <= 0x7f) break;
        newNumber = (newNumber >> 7 ) -1;
        len++;
    }
    //reverse the array return it as a buffer
    tmp = tmp.reverse();
    return Buffer.from(tmp);
}
//matches up with c++ sizeof function
function sizeofInt(number){
    if(number < 2147483647) return 4;
    else return 8;
}


//test hash 
let testBuffer = Buffer.alloc(32);
let testBuffer2 = Buffer.from("84f31c3a347c9b0208a043267b5f3ca72e57c6f5f45a54932c51b4c3503301b5","hex");
let testHash = blake2BHash(testBuffer,testBuffer2);
console.log(testHash.toString('hex'));
let ptProof = deSerializePartialTransactionProof(input);
//prove it

getPartialTransaction(ptProof);

/*
        TX_FULL = 0,
        TX_HEADER = 1,
        TX_PREVOUTSEQ = 2,      // prev out and sequence
        TX_SIGNATURE = 3,
        TX_OUTPUT = 4,
        TX_SHIELDEDSPEND = 5,
        TX_SHIELDEDOUTPUT = 6
*/
function getPartialTransaction(proof){

    //foreach component hash the elVchObj then check that against the elProof
    let checkOk = true;
    let isPartial = true;
    let outTX = {};
    let txRoot = null;
    if(proof.components.length){
        let txHeader = deSerializeTransactionHeader(proof.components[0].elVchObj);
        let mtx = tHeaderToCMT(txHeader);
        console.log(proof.components[0].elVchObj.toString('hex'));
        txRoot = checkProof(proof.components[0]);
        console.log("txRoot:",txRoot.toString('hex'));
        if(proof.components[0].elType == 1 && txHeader){
            for(let i = 1; i < proof.components.length; i++){
                let proofHash = checkProof(proof.components[i])
                if( Buffer.compare(proofHash,txRoot) != 0){
                    console.log('proofHash:',proofHash.toString('hex'),'txRoot:',txRoot.toString('hex'));
                    checkOk = false;
                    break;
                } else {
                    switch (proof.components[i].elType){
                        //TX_PREVOUTSEQ
                        case 2 :
                            console.log("case 2");
                            break;
                        //TX_SIGNATURE
                        case 3 : 
                        if(txHeader.nVins > proof.components[i].elIdx){
                            mtx.vin[proof.components[i].elIdx] = proof.components[i].elVchObj
                        } else {
                            checkOk = false;
                        }
                        break;
                        //TX_OUTPUT
                        case 4 : 
                        //the elVchObj is a vout
                        if(txHeader.nVouts > proof.components[i].elIdx){
                            mtx.vout[proof.components[i].elIdx] = proof.components[i].elVchObj
                        } else {
                            checkOk = false;
                        }
                        break;
                        //TX_SHIELDEDSPEND
                        case 5:
                            if(txHeader.vShieldedSpend > proof.components[i].elIdx){
                                mtx.vShieldedSpend[proof.components[i].elIdx] = proof.components[i].elVchObj
                            } else {
                                checkOk = false;
                            }
                        break;
                        case 6: 
                            if(txHeader.vShieldedOutput > proof.components[i].elIdx){
                                mtx.vShieldedOutput[proof.components[i].elIdx] = proof.components[i].elVchObj
                            } else {
                                checkOk = false;
                            }
                        break;
                        default:
                        break;

                    }
                }   
            }
            console.log("txRoot:",txRoot);
            if(checkOk && txRoot){
                outTX = mtx;
            } else {
                txRoot = null;
            }
        } else if(proof.components[0].elType == 0){
            isPartial = false;
            txRoot = blake2BHash(proof.components[0].elVchObj);
        }
    }

    return {status: checkOk,root: txRoot, tx: outTX};
}
function simpleCheckProof(component){
    console.log(component.elVchObj.toString('hex'));
    let hashed = blake2BHash(component.elVchObj);
    console.log(hashed.toString('hex'));
    //check the hash against the branches in the component
    //loop through the
    for(let i = 0;i < component.elProof.length;i++){
        hashed = safeCheck(component.elProof[i],hashed);
    }
    console.log(hashed.toString('hex'));
    return hashed;
}

function checkProof(component){
    switch(component.elType){
        //TX_FULL
        case 0:
            //?????
            return simpleCheckProof(component);
        //TX_HEADER
        case 1:
            return simpleCheckProof(component);
        //TX_PREVOUTSEQ
        case 2:
            
        //TX_SIGNATURE
        case 3:
            return simpleCheckProof(component);
        //TX_OUTPUT
        case 4:
            return simpleCheckProof(component);
        //TX_SHIELDEDSPEND
        case 5:
            return simpleCheckProof(component);
        //TX_SHIELDEDOUTPUT
        case 6:
            return simpleCheckProof(component);
    }
}


function safeCheck(branch,hash){
    console.log(hash.toString('hex'));
    if(branch.branchType == 3){
        //change the index to deal with the powernodes
    }
    if(branch.nIndex == -1) return null;
    //loop through the branches
    for(let i=0;i<branch.branch.length;i++){
        if(branch.nIndex & 1) {
            if(branch[i] == hash) return null;
            hash = blake2BHash(branch.branch[i],hash);
        } else {
            hash = blake2BHash(hash,Buffer.from(branch.branch[i],'hex'));
            
        }
        
        branch.nIndex >>= 1;
        console.log(hash.toString('hex'));
    }
    return hash;
}

function deSerializeTransactionHeader(serializedTHeader){
    let thObject = {};
    thObject.txHash = serializedTHeader.slice(0,32).toString('hex');
    thObject.fOverwintered = serializedTHeader.readInt8(32);
    thObject.nVersion = serializedTHeader.readUInt32LE(33);
    thObject.nVersionGroupId = serializedTHeader.readUInt32LE(37);
    thObject.nVins = serializedTHeader.readUInt32LE(41);
    thObject.nVouts = serializedTHeader.readUInt32LE(45);
    thObject.nShieldedSpends = serializedTHeader.readUInt32LE(49);
    thObject.nShieldedOutputs = serializedTHeader.readUInt32LE(53);
    thObject.nLockTime = serializedTHeader.readInt32LE(57);
    thObject.nExpiryHeight = serializedTHeader.readUInt32LE(61);
    thObject.nValueBalance = serializedTHeader.readBigUInt64LE(65);
    return thObject;
}

function tHeaderToCMT(tHeader){
    let CMT = {};
    CMT.fOverwintered = tHeader.fOverwintered;
    CMT.nVersion = tHeader.nVersion;
    CMT.nVersionGroupId = tHeader.nVersionGroupId;
    CMT.vin = Array(tHeader.nVins);
    CMT.vout = Array(tHeader.nVouts);
    CMT.nLockTime = tHeader.nLockTime;
    CMT.nExpiryHeight = tHeader.nExpiryHeight;
    return CMT;
}

// return the index that would be generated for an mmv of the indicated size at the specified position
function GetMMRProofIndex(pos, mmvSize, extrahashes)
{
    let retIndex = 0;
    let bitPos = 0;
    let Sizes = [];
    let PeakIndexes = [];
    let MerkleSizes = [];

    // find a path from the indicated position to the root in the current view
    if (pos > 0 && pos < mmvSize)
    {
        Sizes.push_back(mmvSize);
        mmvSize >>= 1;

        while (mmvSize)
        {
            Sizes.push_back(mmvSize);
            mmvSize >>= 1;
        }

        for (let ht = 0; ht < Sizes.length; ht++)
        {
            // if we're at the top or the layer above us is smaller than 1/2 the size of this layer, rounded up, we are a peak
            if (ht == (Sizes.length - 1) || (Sizes[ht] & 1))
            {
                PeakIndexes.insert(PeakIndexes.begin(), ht);
            }
        }

        // figure out the peak merkle
        let layerNum = 0, layerSize = PeakIndexes.length;
        // with an odd number of elements below, the edge passes through
        for (let passThrough = (layerSize & 1); layerNum == 0 || layerSize > 1; passThrough = (layerSize & 1), layerNum++)
        {
            layerSize = (layerSize >> 1) + passThrough;
            if (layerSize)
            {
                MerkleSizes.push_back(layerSize);
            }
        }

        // add extra hashes for a node on the right
        for (let i = 0; i < extrahashes; i++)
        {
            // move to the next position
            bitPos++;
        }

        let p = pos;
        for (let l = 0; l < Sizes.size(); l++)
        {
            // printf("GetProofBits - Bits.size: %lu\n", Bits.size());

            if (p & 1)
            {
                retIndex |= 1 << bitPos++;
                p >>= 1;

                for (let i = 0; i < extrahashes; i++)
                {
                    bitPos++;
                }
            }
            else
            {
                // make sure there is one after us to hash with or we are a peak and should be hashed with the rest of the peaks
                if (Sizes[l] > (p + 1))
                {
                    bitPos++;
                    p >>= 1;

                    for (let i = 0; i < extrahashes; i++)
                    {
                        bitPos++;
                    }
                }
                else
                {
                    for (p = 0; p < PeakIndexes.size(); p++)
                    {
                        if (PeakIndexes[p] == l)
                        {
                            break;
                        }
                    }

                    // p is the position in the merkle tree of peaks
                    assert(p < PeakIndexes.size());

                    // move up to the top, which is always a peak of size 1
                    let layerNum;
                    let layerSize;
                    for (layerNum = -1, layerSize = PeakIndexes.size(); layerNum == -1 || layerSize > 1; layerSize = MerkleSizes[++layerNum])
                    {
                        // printf("GetProofBits - Bits.size: %lu\n", Bits.size());
                        if (p < (layerSize - 1) || (p & 1))
                        {
                            if (p & 1)
                            {
                                // hash with the one before us
                                retIndex |= 1 << bitPos;
                                bitPos++;

                                for (let i = 0; i < extrahashes; i++)
                                {
                                    bitPos++;
                                }
                            }
                            else
                            {
                                // hash with the one in front of us
                                bitPos++;

                                for (let i = 0; i < extrahashes; i++)
                                {
                                    bitPos++;
                                }
                            }
                        }
                        p >>= 1;
                    }
                    // finished
                    break;
                }
            }
        }
    }
    //printf("retindex: %lu\n", retIndex);
    return retIndex;
}


/*if (!(txProof.IsValid() &&

            exportTxId == txProof.GetPartialTransaction(exportTx) &&
            proofRootIt != lastConfirmed.proofRoots.end() &&
            proofRootIt->second.stateRoot == txProof.CheckPartialTransaction(exportTx) &&
            exportTx.vout.size() > exportTxOutNum))*/

/*
            { txHash
                "0": 218,
                "1": 207,
                "2": 85,
                "3": 46,
                "4": 178,
                "5": 160,
                "6": 26,
                "7": 92,
                "8": 183,
                "9": 64,
                "10": 85,
                "11": 180,
                "12": 95,
                "13": 129,
                "14": 61,
                "15": 157,
                "16": 240,
                "17": 11,
                "18": 3,
                "19": 192,
                "20": 203,
                "21": 34,
                "22": 206,
                "23": 2,
                "24": 255,
                "25": 12,
                "26": 21,
                "27": 1,
                "28": 217,
                "29": 4,
                "30": 14,
                "31": 194
                ,fOverWintered
                "32": 1,
                nVersion
                "33": 4,
                "34": 0,
                "35": 0,
                "36": 0,
                nVersionGroupId
                "37": 133,
                "38": 32,
                "39": 47,
                "40": 137,
                nVins
                "41": 1,
                "42": 0,
                "43": 0,
                "44": 0,
                NVouts
                "45": 3,
                "46": 0,
                "47": 0,
                "48": 0,
                nShieldedSpends
                "49": 0,
                "50": 0,
                "51": 0,
                "52": 0,
                nShieldedOutputs
                "53": 0,
                "54": 0,
                "55": 0,
                "56": 0,
                nLockTime
                "57": 0,
                "58": 0,
                "59": 0,
                "60": 0,
                nExpiryHeight
                "61": 239,
                "62": 50,
                "63": 0,
                "64": 0,
                nValueBalance
                "65": 0,
                "66": 0,
                "67": 0,
                "68": 0,                
                "69": 0,
                "70": 0,
                "71": 0,
                "72": 0,
              }*/
