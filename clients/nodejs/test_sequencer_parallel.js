#!/usr/bin/env node

/**
 * Sequencer Test Script - Parallel Contract Transactions
 * 
 * Tests the contract transaction sequencer by submitting 10 parallel transactions
 * from 10 different users. The sequencer should process them sequentially to prevent
 * nonce collisions.
 * 
 * Usage:
 *   node test_sequencer_parallel.js step1  # Register users
 *   node test_sequencer_parallel.js step2  # Submit parallel transactions
 */

import axios from 'axios';
import { Wallet } from 'ethers';
import fs from 'fs';
import path from 'path';

// Configuration
// const RPC_BASE_URL = 'http://127.0.0.1:8082';
// const RPC_BASE_URL = 'http://172.16.12.140:8082';
const RPC_BASE_URL = 'http://172.16.14.223:8082';
const API_KEY = "2919cd546f2c4338bccb4794a3d6afba2282e5729653fc2c2ff6c5e0e194ar45";

// ============================================
// 🔑 PRIVATE KEYS - 300 test accounts for load testing
// ============================================
const PRIVATE_KEYS = [
  // Original 35 accounts (1-35)
  // '11d281397918948a90ce5ce2a72945ee7929a5a932e5bb3d22664ba98f86755e',
  'e41af1d4f1413ed18e0200d225fa810287c5d90d3d11d6fc9723f93538718fc1',
  "b61b1415e8b5e5a3144c0d7b8c556b23baed0366586931011c9d858ecf39bd37",
  "005c880d2bc9c6f560eef60faa20991b68ee25b3b24f3a037c4af5e078cda77a",
  "03c2a0cbaf3a88ddbca8aec76259ff01c9165816794dbcda330ecda5c6008c80",
  "f44356ec40eea5d9f21c7bd2f29bbedb0269d11168bce2ac38f12b4ef5949156",
  "ab71a0afb1ffe76973336a105e14573255863dd4ac5692fac9e5b887ef050555",
  "d12a02464e11ba3d596380d6a2cb854eff3e537c597c69bb9d90639daf85e2c1",
  "bb6ae158bb718b25645f1a545dcf301672c1b10a2bf49b3a08b7bcba62415814",
  "f9a70e39839c17e74af530a7325e55a8796473f32ece2c8284c4c098880a0d28",
  "72321624c6643bd5bbb40be800e063cf4af1d94fd2e2f9ed21321d75a5f8bc25",
  "7f99aa35bc07f235f4bd4688377e5ea865a77f968a1f1669e5de0f05aec2d445",
  "4cf33839b011a638b2a84dcc61fdd2e78320ea49b9acaf661376fb94556cf30d",
  "bec774d1a84f121ffade69bf45a23ddc54278f8fbc4e59680e2835e4185ef896",
  "4592debf089c3019b53f8098f3f1c4ed629e8740a4370caaf6a11a9c85338482",
  "b4221f4b4335926192a4b3a957ca5f0198d7f35f17fa321973bce3be0a5b7db5",
  "e643708c58446c9e3513d11a3bc7531c385f2ee2205037b47dd0dba96239f41e",
  "d9aa82c8b5429c65d0dda7ee04bc2026da4d376bc2d4a305a39af3c45f1b578a",
  "c22462f3e6fe4e288a00a3453f3f93ca5a48cdb29379f8d51394c2c7c91414cc",
  "b83650df6acbe6266fcf52c5288d23d25a2fdc2f2b3564a5825d3a67172c6610",
  "25d16229200a6f13b13548ddd39f104f5336b0cfd984fee6253456efd8bffdd5",
  "728c87ca02ebe88db24398b18437b4a71525808b17158a9bc8fad7005c1ebc84",
  "329625232fe2001268a33c0a2a7523edfeb04138d8db0c18a7697221b4100620",
  "63a9da98227c2efd52498e6a51ccf5640aa707e5bee59e8b5848b3a547e9ab27",
  "01998933eb0d0aa0b51dc41796b29af3142f9039c2138947aa330bfff17ce8b2",
  "a5d6d05532a0f6ee1de3586a2da787429a8b62289d776ca084783c8dc9ffa5a7",
  "15d5488130680e229fb5edceadec7c9a58b6236b5b5c08e339f89236f3ef59b2",
  "4289ba4c078eb7c639b72f3b253e03fe6420d64a3e2f60b2a6f6046b9e6d5010",
  "a28400d43f5f00f95f5ffbfcd1868fd2412685a4695a7dff65ed486488f651b0",
  "8484b8df03e271b07278d61bd97360079f109dfa9bc32af2166873dfaa790415",
  "11ee773c87f7be24e590648091da68546d2273596ad4d0c941e9df078e06e3df",
  "d59977f42a29d6604c97ece9e514e890c4d635537c82acfb6b28856f9195eb9f",
  "21bb33fee6969b26a87f777f77b7c206f3259015db5305eb0e3b2a7dd42d36f1",
  "94bac31302d892ae2c1e474ecb0483475577ff716df6bd383a2094395345fdcf",
  "9bb89847d2252cfd377d89e0ff64fb71d32b18d1dd70be86169ae15fb780e7b4",
  // // Additional accounts (36-100) - Properly generated random keys
  "83ed11e04b47ea2ddf6130d1d1e57e7a63078c7d5f3b0dfd136054335459997d",
  "0744de5c810af18e045ea8e23264f1e368b06effcd92cbff951a545b914db485",
  "430eccbba791a3821bcb498112cd5ab8f42f92553b442e12698ecb529e27d79c",
  "5f21ca245b2e69462d025b3df2265fdd4e34aefe4857c8dd6a9b1f9593d57453",
  "9747ae861601911486295f1ce05d1ecc09995e60894849979910a78210605d5d",
  "a3a08c55a520276a44caa4f1ad3ab7494a633e748fb34e530bdde6cff4c8f504",
  "a9e3e72ac8874ca79f3e4455f92bfd604c16bb085eca629f19ffa749b21bbdbd",
  "1f4b868c9980ffd719cc0ff04a60fb5a9e0bb19ef63d6dec816e073a0b32a11b",
  "d3678679ad6736eb2a038586074080fbcf6c2c4dcd1b0dbc03943b22ad1c9337",
  "53d33be392a8f91bfabf8bcde8609c66c2279f822e3ffe7ddd9893decd6f34e2",
  "2597682530a68b675faf23ed40de098f4b4cf6d39559c4ac91799765390f4ff2",
  "a76315f5245864c5693abe949fce0abbefed94f81910a4201197a3f447e75d7a",
  "406879a4915c277bb494d4c83bc15d6dad9583beffe69f390679c5488b4dd4a2",
  "d49a7279f50f8fd38aaaeee8a1aa7e48ef9e46b9bfc3e0bbbbcf0bf3b1c5d945",
  "36be6f827fc63a1eccee04e42a685d7a3e904fe149b2c02f9e0ec44b00af1e16",
  "7c8e2f5ca16f01a88c1f0c0c0f92c4d625d65a5694dccf82e51942d3d76e725e",
  "328cb8adfcddbd775ff5b6ea3ef76d2816a974e3a75ea6bf9eef94bf46de1e91",
  "f897523eb48f0a3460f2508745d3134550c56fb8816851f767e153b4832d7ca6",
  "aa0a52db93305df781884607ca0578cfb8f248a5c575886a82c8b7ee72c9bed3",
  "d7b3c232c06ed33f73c3d1ae1a055d224ed9687d986a02acae482f014283f4fa",
  "5ea45e6acf77a49db5569276b32845608d9eab7fc3934a4e1449ce5083bb78c1",
  "67adaa4124903359708879d73d2b41c7f99323ce0ec509b25cee08ab24269ad3",
  "f146570355c331668b02d93e36e43c350015efaa8549648c96a72d6cbd72b9c0",
  "f75d3dc31315db0e7226f275743dd8abe356e69d449e06f515df59c4696e4a3e",
  "a846f10bfc13d583a726e7add3e63dfe7e007b03b913c5379e492b81c18206c5",
  "c7eb0d9ee09e7556ae3e8522cf9644d0880763d2333ddae5d32ed703071de080",
  "2edc3dd3cf6b45d81bfcf12e680b1543c14535cafd890c97c56c5842588990ed",
  "fa8dd033caf0c2874cca327086cfd3d36db7652841cec16188cef4611d38a361",
  "605180c4191506eff9c135cef6f1b74571391045b3581eb3ae80be6bab03a976",
  "5539f967aeb0f2d40e18af4599293014f825b6cd552970c322b5a8b8eaf54dfe",
  "ca18d736f56095c244f0d643ae9face224f657fc03259070ef5e2c92ec73bb32",
  "28c966f4326af4f8e841d8e169da97d5b64b88efef644815e3524479c7ec6464",
  "ece0bc455c6a6810f777660ec54a7279734e3c8cf51f662558bd755812bb310b",
  "44afe78949c91255cf35d57657b485e64e286824671b1fb7c5f6fdc3bf45b3f0",
  "7228f38a6db3362354774bfa0dcd2f6bc917998433a681dd8fa7e83bde1d44ad",
  "42848859afe6b3bf22cdd95d3aa3cf6bb76a18a9eddf6a6d66dedd52f608c968",
  "d8ddc392d2fcf12b6ad3e1088d1f16c5f2028edd5f4aa6a682359c76e88b0778",
  "e9d3650a63edcd23fc451389f1d11eaad658cadd7b8b725e980eaf773c5e4e95",

  "27ecaee2811f7e597a5fbd392aa9a6e1da53277136b4748883891d908b428b9b",
  "6de89124cabdefb59b63022c0427a3bea5637762112373f9d038206b9e71c1f4",
  "fa87426ce482aeacadec19873ae7896380c5351d5d9088596d325130ecdb4b6f",
  "19fa2d8975edd75b2f1a00a990fe09b3b8c93a1802827c7b56b26a0d5f1cddfd",
  "8c4d619474f60c635b7b2a49bc1be6b57bc160f377611eea080abdd79458aab7",
  "5826d2851c15cc2bca6d0cd88a11cff577086c4a6cec0b60fb61c636037f248a",
  "1be2e3a04c0aac9e01cdee0efbf81084d3c82741a7314b5ff13ca2281c447304",
  "3f00d31a1ccab92da8d6ed3389aff8ec2f862f9990a256b5bdbd8281f2bb4328",
  "a13c39b5384c27e411801de20459a237e0f2c6feaf685cd3b1332c56ce0fc039",
  "39423489e58f57ded51354ee8ed5872f5008c339b6fc1a69ce672200c13b67ea",
  "d2ff6234a26aff9e63a2693c33bb7a2c210d60fa10f253566ef8a20eadc32ff4",
  "fd47c6ed55325f019d0962d792a59fa64b2bf792f3be4e6132aac13777a9d98a",
  "a9b9e65588ce7c6a848f1c1b774fe97355df42c320dfe1f4bb7f080e6502886d",
  "a68d106da7edc096afc315832153baf0fa44390b21dde28cbb8cab83318af549",
  "bd38393080ca0608a825dc2555e60e1c6c1a54a5a3d45ac0d6def14503550d98",
  "ef137a62fa9c0ab2a0bd13d4afffec895424952f96bb3536b8c0fdd616b10778",
  "f74194d2cc8893a0c814455a22ffc6895624eea4e2e4388356002fe8b6aaa3c0",
  "0ee6024eb7a687b8e0f705913ce232079437105f05616abba45b048b1f882fe8",
  "da794137eb016a06e6f97375298e189983efc8204214902eef884bdb0e79927e",
  "bdf8f80d26a676c94739e77584457de74656f47ad86c0fb9304e0171f5b38dd2",
  "168a0ea51e814d488fb0f6c009945ffe494a907e532e633b6d1acc3cb540e11e",
  "becc8bed64b5d1903dce291ef4ca3a28dd5989c9038a0251af0837701bf6f441",
  "711e69106ae8e40f7025f8b022832c4de4c408b8d1ccd563d4b5253b980007f8",
  "a509030a43112192c1dccb98db6a9b007ca429650bd236dd59cb563e697e8659",
  "b2acb26353bae773456ffac2d868d4e73de0bbaf4ca9736eb657850865f67bab",
  "288990be0f0738937f9c29e2d679bbae87ccc6ef9a47f06dd0a4d2f1d256a31d",
  "f10d67d9a25621e81b8c4449af44133aeb4b4484d0212c5385aa4134623ffe1d",
  // // Additional 200 accounts (101-300) - Properly generated random keys
  "2e891c4df3d3c0b3625e6751c19e90c4627bc39991c657046beee4ca7fb73e05",
  "034e62c4380af98603d87d7abf18c57d028bf3cdba635ab7574a0754e9c98dca",
  "5f4beb571e429b37a1b8dc008b5e81a1ada77ddc8bb2d0d3749ba6f12a8d8b29",
  "b68de4a69318943d3718fbf6d1bcd9fd1b61e6fc0158c69709b90b043b2ff28b",
  "214fec952eebe73defa23bb727bc77fa9c93ae5e313d7eb994fa33d3f3f021df",
  "a6f3a4f92b3461b9071c4594a0b5c52144f7ea1daebc368285bd68f548012982",
  "6195e40944042055174bd9fbc2481d6b41192e5cc059b0cf8c136dbb5881f2e2",
  "323bdf5617d1deda889bdf59689131b202411f85616be098ffbff32bfda63069",
  "a0f8a492d449b90591caa7357b42d1ce098427cdbab2cf3bcc663e4ce1558d4b",
  // "e34894d12b2549b5d007c87692419a4eeab7e196ce049e61934d06baa57f89eb",
  // "8a36aff116bb7de5b81d1e0639f9a7cc0ff72c6406e2b0c2234b74b633a563ac",
  // "36411b3c9bf1ee28d867a102939ddb63cd661d90a9db5e28a62c5dff92a4665b",
  // "e46c3fafd3aaeba93fda80eccbab01506a79e7025c41d34231954e3780ae19b7",
  // "542254c961bc8666efbc683ca379353526bf7a05cf6416f19aa297799544574b",
  // "2bac96fb98387a7d3277fd736329587ca7f6414b6d09f2f79d53cd173a20701a",
  // "cd05ec519bc75735b9d42634105378a691d257d7ea3382cd9c01b3a9011ee48f",
  // "028d3f6d56405cb733c322f9841490b0cf02e404f7a1ec45a069aa9beff9eb34",
  // "6a45ba4143b63e4f752f33d35d583db0ce3157fa529ea2a65f5595850ba972d8",
  // "4c5c430c7546905fb0041ed02f51d3f1d82cf0a70bc2ef1bea0fdd5f3233a3c1",
  // "fcf3c71ce256510ef7274e28fd377add56d3a520df05b87abdc78d5cb99d745d",
  // "66fbe061b89f8ba8138ff45f6cf2407230e1de70f68eedc622b2a2165ec6a584",
  // "d429012b2bba35c500c53306b9fa0b53b3c57c29f2d9cadaa50aa195c6b0f1e6",
  // "ea6dfdbea471aaaa4ac32bb7bdc9a9726a646fd0c0df1e85f2834163edb3deb8",
  // "a29542006701556734a2758ed01ab3d3a8e153d59bca7ef9b5b16e69d2142f1a",
  // "2d7239d838f430fa513924dadcb7509fe78ae9f049de9cc07246e8234d2a49ef",
  // "1a3a6bf54947505d6ca55ec5fcc65ea43a6d4d11248d0ee18efc989401c13131",
  // "5eaad9d7063bba327abda5c60dc45d0d29171fd690eef53acaa3410f8e81474b",
  // "d0d8b33f0050fe7d5db8d0383a2dcec428a8f3fa2f823a939ea4f005d6ac04e7",
  // "c0d25133fbf0c37e1d1a823c1777989a17c6f2d60f8712dc78ceb19736b2bef2",
  // "0c7fa60ab0f05a6899e38c1f85040ad9ae71e76a5c6d917e625f3e554fb5bdd2",
  // "b0bfd1608b1d0f56fccadc1c437b838b320cd444ec6d85a2a39d186b21d7fe30",
  // "14106a78adcbc34dece37fbb366f7a9cb478bdff249ad90126acd457535a38ff",
  // "d10a804245a67250bece8e4bc43be703cc2eeed7958020961ea03cca9bd31d96",
  // "04d89f804e056d6a1b067b34e1f79ba83b077181ca2f24e69f7716a53bd732f2",
  // "dc961a664ea02240f27db8335f808890f5f81c9d0c4bd3a084fc744bbf2f798e",
  // "c3c71f1eec5227e8acd32c5bbf2025619ca83e9363c342351582a84cf73e9189",
  // "4af9c96283b2be2d3a96fd15f178f580f390abb8d5bfe01d1cf24d13f1ab0759",
  // "c46f4d8ca5d34337a073358d89652dd96ccd834212b02d98e0ecb5e14845496e",
  // "25dd71e396eabbae390282c931cc3ca61fd4280764c42d509248ad49d3893065",
  // "8dd3bade7e2136fc3ed54d066dccb65de9a467b05cbfde4086d3c297aafbc924",
  // "14d5348a7fd1bfb2be85541e9c019d3cf7140ae61f8756f2a7a7d26ba79b8054",
  // "0f749b22741d127a40c8e3f1340e1a4a8c0d0ede1128104a13d67f28904c6ccf",
  // "455ca6d7b38a1dd3b469b41188f08ad3bd321eef8fdf540fbab5d31a859ce786",
  // "93ccf61263a6699494916867c0a03b4301efc5bcbdfe9a65d89725303fde58ae",
  // "9b1ae46b72904be2ee8193259563b63877365b223989703bb135ee2462b6dde8",
  // "eb67352f2c4455a4ef8c7baafa6a820be1b41a064b8df535d7dfab01e8098813",
  // "4ef8736414df162bbdac8c86a12d19c9d6294b03e2a062c34b979adcb227a807",
  // "3193ceea4aa04eb475cfded43f2ce9018c063bea659b43ccb61e6135caa07bab",
  // "74751136e0e5c5d5b797f2b8300ab96da2d633c387548ba595c7fd73da78332f",
  // "fd768e2a5c1d3cc6d6e6709fb17e3f69491d62e54be397410ce397706ef7474e",
  // "11233b9d4220b62fcd2dfd7cd481f7cd3c14fa11461048d82731dcbd9ae2e141",
  // "bfb10b806acf5d1895b661c2c91818e9b0f5439922545e406862c06e76311e20",
  // "749e64a31d6fb066cbafb2887642e4ff10780fc9d9b413da028b83add13ef679",
  // "5e53ed5122fbaf197b2ac4c24f4a37da6b2c67c7b49ecc7333ef6463fc9ca302",
  // "c4109d13b87bedc0a8af7b48eacc581a8b463f7bb743bab060242e0cec5f38df",
  // "de5801a136b17831e4ceb53166ad72f76384c0364099fad8a030a54785a0612d",
  // "7819af1439d580c8768d95444ec5b8919a4f2e745adcdf4c996d4ceb0ea85cb0",
  // "9cfab38ba019041de19b8b139551cf678a21ca5df8726256bb37f3779a3c9fbf",
  // "711babb276427d72e79ec88fd86ffe4b3f588174fc34b7d295594bbd1240f895",
  // "9c547e2c52c1758367ddae96701524124c0015075628161fdd159351d1982ffc",
  // "357891d156c55cf368ff4d75c7c58b1952eb23066779da4f4fdb5f42d128e216",
  // "3cc1666e52a6009a34013e6173e13575b9a065783b556fbb6387e37d65b6cae7",
  // "7ea026cb67b24fb42359580f5c4d762fcaa803a60fc708c95843dd80c34f72d2",
  // "0556c840e20d60f8bc835b2192a1c7b1df5d690e88d84565b2bf7a02a5b577c7",
  // "092b9e3bcd04ccd43d13c52bacb6942c2f13eb7d9804260ce68f6333401e390c",
  // "bfdd543c47c572e445ea4b8053ee34d11b1095bd8333485bb13be97f5a00b8de",
  // "c608095512a25a49cb395ac9596990803d6f9bb897c31db95711e190fb321ecb",
  // "8d0991f6ea97c60ffd202edca456370a6980c53e08b99afd6e637318ae54f780",
  // "21c228ca943d218ca937b6976fc73adb6187350ba813bc0dd1ee48c3b314d9e2",
  // "0442bded36c12f32810ad0bc750cdaf8897af24d44a63bda2cea8f2d1f4c067d",
  // "f4a264db00d16db2741baf29c75583c9f01221da8afd97210ee62160168e0d2b",
  // "09aa9303de1daa31cb1ee442b6299442e82b49ca75cd2c314ca78439b2f01f3b",
  // "39ec755dc5faa69bbd3bb2e3bd714ecbe6323beb6cee9d19db5ac0bc85b0ac94",
  // "4ab1ebee4ca749ab56657a518c1640e6512741166f28c8f8d14aa758c4d715a7",
  // "834ea2678934b410e7cb4cde11e52168567a12ec3968312b44d65a4f75a2d4b6",
  // "6cfbeab194ccd49247b77dfd5e1b0e2ed48195c452d57498fc86df751f86f544",
  // "ce84ee72c42ca10abb0c5f3cff6eee34dc3ee24bfd39a7bee7f35c6b0140cf63",
  // "c1e3e33c8140406463fc0ec004a7d539918d2725b86e637e2b7e430022de6778",
  // "aaababd79e8af92cbc9c364eac1baccd7e11b9ec79843f1a2054e491b9f4f649",
  // "d3ca1fdccde010bea228814ec791b29c321b6ce9f355c38750e85635027a52b1",
  // "64e48674976c511d58ab83cb83765d4ee73d63f47d9aa68164320dffa88622e2",
  // "72e131910582646ba8d6c0f2463a2b39cecae20c227d4cb621de651519db787c",
  // "52e774385deaffcdee3007b07ddbe2b1ef5ed1d340ae98a872d61d39b6f87626",
  // "636be1660d488c1734451cc121398b412163843f47f66981fce7d0d76a530a70",
  // "058ad2fa65dee3405505750934f0a421295f83af47e015b920a63ef21e52a7e4",
  // "beb050997c16154fb71e1cab3d925b81d7806817af9a230c4741c544080b3978",
  // "d07ff0a41734c19d7bb797f89030d8b0581ad9fe7a27b37aead8ea78a14cad15",
  // "a267db7ee45271cbe39b54a2e8fb7d87d894450ef5de1a2a6e7af9508316422d",
  // "7ccd0994bea5ce9c8c58b779519491d85f0516c521ba4601132ff882862fb266",
  // "cd3429ae392f0e898dc77500e621d791f0fbb4ce4466440de35a637fd88db3ae",
  // "146ba84ab55664e9b31fe7142639a7718927a094858dbe2a87b6846911ee6cec",
  // "3dab1a99a50623846c95b9ef49666336dcf338d038d99d035ed2230e71f4800c",
  // "a1e0e07d1fb4ca6d6b876aed39f024964f9c652756929c53ddcb5ae3bc16dfc6",
  // "9f65b3b55ace29ebdb3b5a6ef1107ddb80c09daabb64f4630b71e3ec45da9d9a",
  // "ad3fc30156069bd165ee27c587263181e722fb63a12d2ddebc81126431225a53",
  // "9025ee8b3884a60b4b84e080c57be449a250760ea5f098ec8fcbc2d0cbe8559a",
  // "67e0c51c514acf2293377ec08beb7ddef96d4c9c76872530011c78e26491455c",
  // "2abc9390fbcc26b9ae30c9963c253fc0e36b67f831863c01212ed486c68d3b20",
  // "fd7b184ad2645fe7daded03a797fc408ae535a8f925f2747af9aae4b22f61718",
  // "0f458c868485393e791961727a1bf7b62776070867c7098128c25f6e91315ecf",
  // "77202a38759b65197f6900a622e94bca93b24e26e1f51474e157257c1ed5271a",
  // "c7f18e7fd093ebbd437168ed28cdfdf0ab3a7f50f830cce152eca45527139da0",
  // "362ea560efeabaef703ac59d1abf6c920a79998b03ccf774f8fb62338c988ce9",
  // "8a824eb6778a2a10e6dd801b89a13e4f8bf31da15eb144e9dd481b355a4c4fea",
  // "3d9d18673643b9036a00920d814c49d2ebadf1c99804956dbc21806d4a505e0c",
  // "5469b34dc7996430e336afdee8f0f721d42729afe498efe42566f0182f1f6494",
  // "cf467199110957723b035a59bb73636e1545dab80079459ce22f24043244cf87",
  // "32d2cf5a45c5201a5b302b29ff9cb5a3588dc4b33ac536d498d0f5e28cb1e251",
  // "b42f79cb0487484423a2a143a1a5138b1b23f6d737b394cbff7823abf87266aa",
  // "77404a36291fd13bf81ef5ce5cf13f27c25a6700fce49a23e522c77abd783a86",
  // "ce3bf1833662e9e783d872ccb50367b1df487f8919d0aac170e1d9479cb0d628",
  // "a73e3f5aaca01fa87e53e2237e5a134468eeec5cb1730ac37b70a78cb1f5b8b1",
  // "8587f86691579b2085ad7ef4f7a940befda534840b63722767c365272ea43111",
  // "fd063a8911378a5b9f4a8b538158fbe24eb83e15da1251744ac5b379fb06ea12",
  // "e9ae1c43f27d6c95eb21047bf65605062e3e22ea6c95d40b8e2daa985c93a577",
  // "97c3a17d65d7b737d7d5d4f51b1a9323e097757bc8a1b12a9b3adbeba98943a1",
  // "ad0e9407eda23801eff318d718219ab46077c6de03b618dcdad9683dd29f6bd1",
  // "d143baef46102d76a15ecf2dac3fc603dcee4b40ea16ee0080d9f62f85b322fb",
  // "e3fb8a509116564a5f89af8fb1c0614f1924eedbb2a49753eb2d7c3d63003523",
  // "a6351f8984c0634fa0d4f94c6ecad736de9ae67dd344cb24496fec2b706cb841",
  // "c6bd8bac5a16994f8f2197eb1335137d75ae8c867e7a784facfb74b5fb94095e",
  // "b13a1a1252e3797f68a273eb55e60a7d08f65dccb20790e7e2f7aa8c8854fc7b",
  // "4b28a1e68f0de7a95e245aae9172bc1c3b8466539b65cabad79fa895b3be308a",
  // "01baf5299fa2a5dfdacec63121dc73a1ad4ff37fb746fba34db269233018326b",
  // "2cc02970d41fc40ba2e3e9840a9726e2741860ba21b2943f50c3e947e9ca8745",
  // "8bffa4ff77a54d03747aff49e99d557723e8363e434fdeeafb24ba49d1e30f47",
  // "5ab8a79a0b42b9f65e614de3272726a249cb9c7d7679b2db53ba030a09dce80a",
  // "52690d0717727ef0567686f140860d0071428aed1ac5b68fe6dbaa5cc1902e34",
  // "12eb374bd911f169e56302a8227b3b8410c74547d508aaf90ec94587c60ab844",
  // "1ef90c396d01eee0bbf18b47b0a691b76bdbe7bf05ca5ade1ecb5d88dba37b64",
  // "2424796123980eccdabd5b9952cc706f4b9380bb54fffded9f7d06c8a7dac7d8",
  // "f6545c721a5fc23e0eaaf25e652a3baf381f8953f14f41bd95ab1a29da838528",
  // "811fa06e07f9ec17eb4d23772c9bdf076959599890f2950b50b611e03bc53850",
  // "6493461e3b1c1e85cf8d47100619ef9e57f30301cfa383961647c95d5ecda2ec",
  // "5f8cb72fef1bfa942a48a5ff1910f0a84021c462d01a9b1ed25cb91122d2304b",
  // "995e2f372277914c7c5989952e2e6be2cef707fbb54b7c565e483a62a241ca84",
  // "0d8ab37f80b6590b2a4c355f2e514119bc4001a45db513b45892471f1d2e93c0",
  // "d4ac987f9ac108b973a23c12a346d4f64eb7ae8aee26d244e7a6214013c5d05e",
  // "2b4fce3b1c286823995795fca5606c5a15a1b685505ae954281cbcf612bb97f8",
  // "d985f0882e7737dae6e816c172bf79d13741c2e9839e8830c75dd3cab5b06c5b",
  // "1d9abb98465a0fdf4a1d674e812245177865da4a404ad6ce825f5c29d6066bd1",
  // "9b9eea5c96c90cd345268d1b51d719ee8ed47ae79c99deaa6c822698b8bd0c29",
  // "609cc81bc11e72139ec93f11ec168b23bb25e510adbfb073beaa43188a9651f2",
  // "c41d856f26266221d297753b3c0febe43cfde65d3f439f4209f0372f1790736e",
  // "ea90685ffa7aae18377738eb46995f211a027d1e17998a6365ca9a5e4bf1de39",
  // "e0997db854714ece8ee50191e8f6a103ab39c45c4a4168e168a923188f79b4c2",
  // "c113dbd23dd630dac6231f1769d28deb24f16754b4bc525c4e815564d99f5db0",
  // "e9b255ad9a0737311d30c2ee1885272b07866bc18159f3a759689032299f244e",
  // "33af9729082cd99a955dc1e468444444cb6f85ccdd2066857ed1a95bd6e5e06a",
  // "c1531fe6a33ffd404502082e300b9fd6951455051f91c25fa25df432314acc6e",
  // "233cb15662e16afdc8a6e7963bf52ec17631ba2cbeeb9996b13f9085821c4c38",
  // "94cb845e31aaa50f18803893b56abf564b20d8fc20d8001064ff85d44ae759aa",
  // "e317d38a6102e531358a449413b681d9a9026eb6af544f4697baf54f7a941d3f",
  // "aac1f8ab2cc96dc4edb88fbfb9c52a9548226711f0eb0a2eb8e7a6a1f90e2d53",
  // "98a4d44d2d4f689ae5d4a6841b75170c4088819ed67f6dc1c7c4f8342d7724a9",
  // "dee4df71225b05390ede9d67b46adb335d794cf685afac391bdfb05f80d794ff",
  // "0a5f64fb71e5983235fd27ff6fb8643d4905f1c9fb2d71fe5fe2a4183a0ffdf7",
  // "6c7538cc55af867c30e196708791272111223a137827d7e6278b8a3accc0fb7f",
  // "639db60e5da4bc7610456b589462c8451ade53f6cc025b7e33dea92663bc8a07",
  // "ac8f5e8bade7902cf49d4065168d70ec2ae5d226fd7be6b7eaa09236031f51f4",
  // "f3aedb3942b0802682a74d24b115d45c94d516f7d0e5959a129e98a55c674ea9",
  // "b6356013b64ab83380e83b871f1064f78c6cfed8256983030a2edd0a72799494",
  // "92e73f79831c48e04c21d5314140a5aee9967781bb85afb1588a4bbaa333dc9a",
  // "5c212fbab74a133919a6690d63b7a08147b964ef72127dc98607e15ee2f6ae06",
  // "a246cd7c70af06a48de76de7aa54800de1ecbac471e45550194813825d8ac47e",
  // "e08cde7dae6e5a245fbbc34cce1e46d40a89a0f04ac62e780f1ff0498e9fd09c",
  // "b4c721f7d17cdbf776bf8a29f3b02b985c9366d37083982b7988183591007414",
  // "ee0492902b2202f9a19937733789e1788cd83fff792d9f79415a0002854a473d",
  // "e625bf34c2648c94bc4772c0ee6a31b0464d4801d61bf0c0f95852c6f0fb50ec",
  // "b84dfc7f4dd2f98844defa16e75ee3365c51f4168b83fcd220058924c76c5a92",
  // "d338494b693cbb7ca9b08f0c703ee3e5f982da47314a61e092562d3b31b5ace7",
  // "e468e6b61650f76069a8514cffaae48fffc140c8f81fdd76427237290f2ca1b5",
  // "0c044fcd0cd9e49918fe6d47b986b90105b2db43964dce52fe147533f28d3170",
  // "56fc68063bfb01098159a51ce730d4e7c4097c6b755d5ffd158400b3c7288174",
  // "b287c3650711b9268d96660aae15f36ed14841b0fcb82935abf6c1b6cd75b31c",
  // "a921b3b068d445ffbb9a108aa5bc1f147fb58f0a7cc8dd9397ad18cfe748a500",
  // "01fbc2a8238b695ee6aee18fd5616ba3ee8eb2a1888e9d6d72ad220a6c612cb0",
  // "5e27131ea474fb707c2083607c8b5535c6d35f26aef56840959c6e5a4505a27e",
  // "10cb399e3f183e697b50ae5db6e9d3de87d3fd47ad6c47999d80098437bbd713",
  // "5bca1dfa9a284f24c050999d302c066c100e785d6aec01ca5e3643edba1686be",
  // "46f832ca5eabc638a61850b5a6e60897ddbc0b6d31ca62b56bc5365c5948ffae",
  // "a53bc83054a0f8dd3d5296fa2327accf8d92c871b55b3eca711e508de849e25d",
  // "e39b565fec259355ed2c302a51da9b11b9e2c1c5698761d6bf894fb539f235a1",
  // "b3627c8e05c12a67323616e7cdce557b2c2eaec3cafaca6496a64f17d1eee96a",
  // "1b456b8d1fddf38bc54615478675ffbb57107356dae2d0fb1da06e3a3a038fd4",
  // "488b44d474de27577aaf0d5c83f65464b3cfa9f538ba7edbb67f197f499a4831",
  // "ab4762babbba0d3ede3f86517d8910210f440093e72b95b1ba06985bcbe7a5f7",
  // "8641ce796436375c1db3cfec09faaf8b9615f55d11c7779956d461eb351ff3f1",
  // "0d6bfc90d41ee04840d76c13ed6d36fa29e0c6ab3f4fb8eb048e77b1a70ffc83",
  // "aa9ebc2bf25ff4deab52546d42fe155da2e031381a604ad3d4f8f8de01e2f104",
  // "1dfe851b454d33723cf521d096c141e3c9364654a67f731212e13c6d05551f96",
  // "470fc0eecc3d3376f1970a57ca20d6e12c42a74ab448884455ea415f08ff152c",
  // "391d0e16eed92bbacf455c67b1175fa048e38adc65f792fedf402cc12e5fbcaf",
  // "2b7be51cae4ff71e331aed298539e0fff45f8c07e9a5b336b46bec6edcef5beb",
  // "358b4c15fecb0de0f36b6f3eb8e807b79f70ac7b4c60be64bd69a4efd07558ae",
  // "c20e1435cf4b8e122dc02267cfe69b40109f1ea02e1ad8eb6e12e9298f77df82",
  // "3b149c390111982a202ed5a70ceb0dc0db0d424aa29086e43b823a6f3717834e",
  // "57c673278d785e8e74146e5239d009d2d334319f2f32b7eec1130febe0fceafb",
  // "2490ec47dbbd0fae14c3a9eadc6c886e9ca8cac2fb34d725c1269e1ad839f2de",
  // "8141e8e2bfe302ea4b63d7c6ac37b03e2cda56918c1312c5724478f4ac77383a",
  // "3c27fcb05a46a7b043ae31c7619058c1d8f9c2d67ea4935d1ee7b70bc9b46599",
  // "b00ed967d107dcd7c1c6a9d3551b992673951c6d3589c849b9c288572d009425"
];

// Colors
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  magenta: '\x1b[35m'
};

function log(message, color = 'reset') {
  const timestamp = new Date().toISOString();
  console.log(`${colors[color]}[${timestamp}] ${message}${colors.reset}`);
}

// Register a user (like test_register_user.js)
async function testRegisterUser(ethereumAddress, userId, wallet) {
  try {
    log(`[User ${userId}] Registering address: ${ethereumAddress}`, 'blue');

    // Create registration message: "register:{ethereum_address}:{timestamp}"
    const timestamp = Math.floor(Date.now() / 1000);
    const message = `register:${ethereumAddress}:${timestamp}`;
    log(`[User ${userId}] 📝 Registration message: ${message}`, 'cyan');

    // Sign the message using the wallet
    const signature = await wallet.signMessage(message);
    log(`[User ${userId}] ✍️  Signature: ${signature}`, 'cyan');

    const response = await axios.post(
      `${RPC_BASE_URL}/register_user`,
      {
        ethereum_address: ethereumAddress,
        signature: signature,
        message: message
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'X-API-KEY': API_KEY
        },
        timeout: 15000
      }
    );

    log(`[User ${userId}] ✅ Registration successful!`, 'green');
    log(`[User ${userId}]   Status: ${response.data.status}`, 'cyan');
    log(`[User ${userId}]   Derived ETH Address: ${response.data.derived_eth_address || 'Not available'}`, 'cyan');
    log(`[User ${userId}]   Derived BTC Address: ${response.data.derived_btc_address || 'Not available'}`, 'cyan');

    return { success: true, data: response.data };
  } catch (error) {
    if (error.response) {
      log(`[User ${userId}] ❌ Registration failed: ${error.response.data?.message || error.response.statusText}`, 'red');
    } else {
      log(`[User ${userId}] ❌ Registration error: ${error.message}`, 'red');
    }
    return { success: false, error: error.message };
  }
}

// Get user info (like test_register_user.js)
async function testGetUserInfo(ethereumAddress, userId) {
  try {
    log(`[User ${userId}] Fetching user info for: ${ethereumAddress}`, 'blue');

    const response = await axios.get(`${RPC_BASE_URL}/user_info/${ethereumAddress}`, {
      headers: { 'X-API-KEY': API_KEY },
      timeout: 10000
    });

    log(`[User ${userId}] ✅ User info retrieved!`, 'green');
    log(`[User ${userId}]   User ID: ${response.data.user_id}`, 'cyan');
    log(`[User ${userId}]   Ethereum Address: ${response.data.ethereum_address}`, 'cyan');
    log(`[User ${userId}]   Has Tweaked Share: ${response.data.has_tweaked_share}`, 'cyan');
    log(`[User ${userId}]   Has User Group Key: ${response.data.has_user_group_key}`, 'cyan');
    log(`[User ${userId}]   Derived ETH Address: ${response.data.derived_eth_address || 'Not available'}`, 'cyan');
    log(`[User ${userId}]   Derived BTC Address: ${response.data.derived_btc_address || 'Not available'}`, 'cyan');
    log(`[User ${userId}]   Created At: ${response.data.created_at}`, 'cyan');

    return { success: true, data: response.data };
  } catch (error) {
    if (error.response?.status === 404) {
      log(`[User ${userId}] ❌ User not found: ${ethereumAddress}`, 'yellow');
    } else if (error.response) {
      log(`[User ${userId}] ❌ Failed to get user info: ${error.response.data?.message || error.response.statusText}`, 'red');
    } else {
      log(`[User ${userId}] ❌ Error getting user info: ${error.message}`, 'red');
    }
    return { success: false, error: error.message };
  }
}

// Submit deposit using user_mpc_deposit (like test_register_user.js)
async function testUserMpcDeposit({ wallet, amount, userId }) {
  try {
    const signerAddr = await wallet.getAddress();
    log(`[User ${userId}] Testing user_mpc_deposit for signer: ${signerAddr}`, 'blue');
    log(`[User ${userId}]   Amount: ${amount}`, 'cyan');

    // Fetch user info to get the derived addresses
    const userInfo = await testGetUserInfo(signerAddr, userId);
    if (!userInfo.success) {
      throw new Error('Failed to fetch user info');
    }

    // Check if derived addresses are available
    if (!userInfo.data.derived_btc_address || !userInfo.data.derived_eth_address) {
      throw new Error('Derived addresses not available yet. Please wait and try again.');
    }

    // Construct DepositIntent (EXACTLY like test_register_user.js)
    const intentTimestamp = new Date().getTime();
    log(`[User ${userId}]   Intent Timestamp: ${intentTimestamp} (${new Date(intentTimestamp).toISOString()})`, 'cyan');

    const depositIntent = {
      source_address: userInfo.data.derived_eth_address,  // ETH address
      // target_address: userInfo.data.derived_eth_address,
      target_address: "0x052e109a83bce9217270ca2880035c9d7de9065e",
      source_chain: 'qubetics',
      target_chain: 'qubetics',
      amount: amount,
      source_token: 'TICS',
      target_token: 'TICS',
      timestamp: intentTimestamp,
    };

    log(`[User ${userId}]   Deposit Intent: ${JSON.stringify(depositIntent)}`, 'cyan');

    // Serialize DepositIntent for signing
    const msg = JSON.stringify(depositIntent);

    // EIP-191 personal_sign  
    const signature = await wallet.signMessage(msg);
    log(`[User ${userId}]   Signature: ${signature}`, 'cyan');

    const response = await axios.post(
      `${RPC_BASE_URL}/user_mpc_deposit`,
      { signature, msg: depositIntent },
      {
        headers: {
          'Content-Type': 'application/json',
          'X-API-KEY': API_KEY
        },
        timeout: 120000
      }
    );

    // Check response status
    const status = response.data.status;
    if (status === 'success') {
      log(`[User ${userId}] ✅ user_mpc_deposit SUCCESS - Transaction completed!`, 'green');
    } else if (status === 'submitted') {
      log(`[User ${userId}] 📤 user_mpc_deposit SUBMITTED - Transaction is being processed`, 'yellow');
    } else if (status === 'processing') {
      log(`[User ${userId}] ⏳ user_mpc_deposit PROCESSING - Transaction is still being processed`, 'yellow');
    } else if (status === 'error') {
      log(`[User ${userId}] ❌ user_mpc_deposit ERROR - Transaction failed`, 'red');
    } else if (status === 'timeout') {
      log(`[User ${userId}] ⏰ user_mpc_deposit TIMEOUT - Transaction processing timed out`, 'yellow');
    } else {
      log(`[User ${userId}] ❓ user_mpc_deposit UNKNOWN STATUS: ${status}`, 'yellow');
    }

    log(`[User ${userId}]   Response Status: ${response.data.status}`, 'cyan');
    log(`[User ${userId}]   Signer Address (recovered): ${response.data.signer_address}`, 'cyan');
    log(`[User ${userId}]   Is Registered: ${response.data.is_registered}`, 'cyan');

    // Show transaction ID if available
    if (response.data.user_to_network_tx_id) {
      log(`[User ${userId}]   Transaction ID: ${response.data.user_to_network_tx_id}`, 'green');
    } else {
      log(`[User ${userId}]   Transaction ID: Not available yet`, 'yellow');
    }

    // Show error message if present
    if (response.data.error_message) {
      if (status === 'error') {
        log(`[User ${userId}]   Error Message: ${response.data.error_message}`, 'red');
      } else {
        log(`[User ${userId}]   Message: ${response.data.error_message}`, 'yellow');
      }
    }

    return { success: true, data: response.data };
  } catch (error) {
    if (error.response) {
      log(`[User ${userId}] ❌ user_mpc_deposit failed with HTTP status ${error.response.status}`, 'red');
      if (error.response.data) {
        log(`[User ${userId}]   Error Response: ${JSON.stringify(error.response.data)}`, 'red');
      }
    } else {
      log(`[User ${userId}] ❌ user_mpc_deposit error: ${error.message}`, 'red');
    }
    return { success: false, error: error.message };
  }
}

// Step 1: Register all users
async function step1_RegisterUsers() {
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('📝 STEP 1: REGISTER USERS', 'bright');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('', 'reset');

  const validPrivateKeys = PRIVATE_KEYS.filter(pk => pk && pk.length >= 64);
  log(`📝 Configuration:`, 'yellow');
  log(`   - Number of users: ${validPrivateKeys.length}`, 'yellow');
  log(`   - RPC Endpoint: ${RPC_BASE_URL}`, 'yellow');
  log('', 'reset');

  // Create wallets from private keys
  log(`👥 Creating wallets from private keys...`, 'magenta');
  const wallets = validPrivateKeys.map((pk, i) => {
    const privKey = pk.startsWith('0x') ? pk : `0x${pk}`;
    const wallet = new Wallet(privKey);
    log(`   User ${i + 1}: ${wallet.address}`, 'cyan');
    return { userId: i + 1, wallet, address: wallet.address };
  });
  log('', 'reset');

  // Register users in batches of 5
  log('📝 Registering users in batches of 5...', 'magenta');
  log('   Note: Derived addresses may take a few seconds to generate', 'yellow');
  log('', 'reset');

  const BATCH_SIZE = 5;
  const registrationResults = [];

  for (let i = 0; i < wallets.length; i += BATCH_SIZE) {
    const batch = wallets.slice(i, i + BATCH_SIZE);
    const batchNum = Math.floor(i / BATCH_SIZE) + 1;
    const totalBatches = Math.ceil(wallets.length / BATCH_SIZE);

    log(`📦 Batch ${batchNum}/${totalBatches}: Registering users ${batch[0].userId} to ${batch[batch.length - 1].userId}`, 'blue');

    const batchPromises = batch.map(({ address, userId, wallet }) =>
      testRegisterUser(address, userId, wallet)
    );
    const batchResults = await Promise.all(batchPromises);
    registrationResults.push(...batchResults);

    const batchSuccess = batchResults.filter(r => r.success).length;
    log(`   ✅ Batch ${batchNum} complete: ${batchSuccess}/${batch.length} users registered`, 'green');

    // Wait 5 seconds between batches (except after the last batch)
    if (i + BATCH_SIZE < wallets.length) {
      log(`   ⏳ Waiting 5 seconds before next batch...`, 'yellow');
      await new Promise(r => setTimeout(r, 5000));
    }
    log('', 'reset');
  }

  const successfulRegistrations = registrationResults.filter(r => r.success).length;
  log(`✅ Total registered: ${successfulRegistrations}/${wallets.length} users`, 'green');
  log('', 'reset');

  // Wait a bit for derived addresses to be populated
  log('⏳ Waiting 5 seconds for derived addresses to be populated...', 'yellow');
  await new Promise(r => setTimeout(r, 5000));
  log('', 'reset');

  // Get user info for all registered users
  log('🔍 Fetching user info for all registered users...', 'magenta');
  log('', 'reset');

  const userInfoPromises = wallets.map(({ address, userId }) =>
    testGetUserInfo(address, userId)
  );
  const userInfoResults = await Promise.all(userInfoPromises);

  // Save all addresses (wallet + derived) to JSON file
  const addressData = wallets.map(({ address, userId }, index) => {
    const userInfoResult = userInfoResults[index];
    return {
      userId: userId,
      walletAddress: address,
      derivedEthAddress: userInfoResult.success ? userInfoResult.data.derived_eth_address : null,
      derivedBtcAddress: userInfoResult.success ? userInfoResult.data.derived_btc_address : null,
      hasUserGroupKey: userInfoResult.success ? userInfoResult.data.has_user_group_key : false
    };
  });

  const outputFile = path.join(process.cwd(), 'registered_eth_addresses.json');
  fs.writeFileSync(outputFile, JSON.stringify(addressData, null, 2));

  log('', 'reset');
  log(`💾 Saved ${addressData.length} users with derived addresses to: ${outputFile}`, 'green');
  log('', 'reset');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log(`✅ STEP 1 COMPLETE: ${successfulRegistrations}/${wallets.length} users registered`, 'green');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('', 'reset');
  log('💡 Next: Run step 2 to submit parallel transactions', 'cyan');
  log('   node test_sequencer_parallel.js step2', 'cyan');
  log('', 'reset');
}

// Step 2: Submit parallel transactions using the same users
async function step2_SubmitTransactions() {
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('🚀 STEP 2: SUBMIT PARALLEL TRANSACTIONS', 'bright');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('', 'reset');

  const validPrivateKeys = PRIVATE_KEYS.filter(pk => pk && pk.length >= 64);
  log(`📝 Configuration:`, 'yellow');
  log(`   - Number of parallel transactions: ${validPrivateKeys.length}`, 'yellow');
  log(`   - RPC Endpoint: ${RPC_BASE_URL}`, 'yellow');
  log('', 'reset');

  // Create wallets from the same private keys
  log(`👥 Creating wallets from private keys...`, 'magenta');
  const wallets = validPrivateKeys.map((pk, i) => {
    const privKey = pk.startsWith('0x') ? pk : `0x${pk}`;
    const wallet = new Wallet(privKey);
    log(`   User ${i + 1}: ${wallet.address}`, 'cyan');
    return { userId: i + 1, wallet, address: wallet.address };
  });
  log('', 'reset');

  log(`🔥 Submitting ${wallets.length} PARALLEL deposit intents...`, 'magenta');
  log('   Watch the node logs for sequencer activity!', 'yellow');
  log('   Expected behavior: Transactions queued immediately, processed sequentially', 'yellow');
  log('', 'reset');

  const startTime = Date.now();

  // Submit all transactions in parallel
  const depositPromises = wallets.map(({ wallet, userId }) => {
    const amount = "13000000000000000000";  // 5 TICS (reduced from 44 to fit 10 TICS balance)
    return testUserMpcDeposit({ wallet, amount, userId });
  });

  log(`⚡ All ${wallets.length} transactions submitted in parallel!`, 'bright');
  log('📊 Processing...', 'yellow');
  log('', 'reset');

  // Wait for all to complete
  const results = await Promise.all(depositPromises);

  const endTime = Date.now();
  const duration = ((endTime - startTime) / 1000).toFixed(2);

  // Summary
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('📊 TEST RESULTS', 'bright');
  log('═══════════════════════════════════════════════════════════', 'bright');
  log('', 'reset');

  const successful = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;

  log(`✅ Successful: ${successful}`, 'green');
  log(`❌ Failed: ${failed}`, failed > 0 ? 'red' : 'reset');
  log(`⏱️  Total Duration: ${duration} seconds`, 'cyan');
  log(`📈 Average per transaction: ${(duration / wallets.length).toFixed(2)} seconds`, 'cyan');
  log('', 'reset');

  log('🔍 WHAT TO CHECK IN NODE LOGS:', 'yellow');
  log('   1. Look for "📋 [SEQUENCER] Queued contract transaction" messages', 'yellow');
  log('   2. Verify transactions are processed ONE AT A TIME (sequential)', 'yellow');
  log('   3. Check for "✅ [SEQUENCER] Successfully executed" for each transaction', 'yellow');
  log('   4. Verify no nonce collision errors', 'yellow');
  log('', 'reset');

  if (successful === wallets.length) {
    log('🎉 ALL TRANSACTIONS SUCCESSFUL! Sequencer is working correctly!', 'green');
  } else if (successful > 0) {
    log('⚠️  PARTIAL SUCCESS - Some transactions failed', 'yellow');
  } else {
    log('💥 ALL TRANSACTIONS FAILED - Check node logs and configuration', 'red');
  }

  log('═══════════════════════════════════════════════════════════', 'bright');
}

// Main test function
async function runSequencerTest() {
  const step = process.argv[2] || 'step1';

  if (step === 'step1') {
    await step1_RegisterUsers();
  } else if (step === 'step2') {
    await step2_SubmitTransactions();
  } else {
    log('Usage:', 'yellow');
    log('  node test_sequencer_parallel.js step1  # Register users', 'cyan');
    log('  node test_sequencer_parallel.js step2  # Submit parallel transactions', 'cyan');
    process.exit(1);
  }
}

// Run the test
runSequencerTest().catch(error => {
  log(`💥 Test failed with error: ${error.message}`, 'red');
  console.error(error);
  process.exit(1);
});
