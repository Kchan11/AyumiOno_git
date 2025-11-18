#include "openfhe.h"
#include <iostream>
#include <vector>
#include <random>
#include <memory>
#include "math/discretegaussiangenerator.h"
#include "multikey_FHE_util.h"

// using宣言
using lbcrypto::NativeInteger;
using lbcrypto::ILNativeParams;
using lbcrypto::NativePoly;

using lbcrypto::DiscreteGaussianGeneratorImpl;
using lbcrypto::NativeVector;
using lbcrypto::RootOfUnity;

// このコードでは低レベルな多項式を直接扱うため、NativePolyをPolyとして定義

//2人ずつ並列化してXORすればlogn時間で計算できる

using Poly = NativePoly;

using namespace std;

std::vector<int> GenerateRandomBitVector(int n);
std::vector<Poly> EncryptBitVector(const Poly& pk, const std::vector<int>& bitVector, unsigned int degree, std::shared_ptr<ILNativeParams> params);
void PrintBitVector(vector<int>& bitVector);
vector<int> GenerateLongPad(const vector<int>& seed,int len);
vector<int> XORvec(const vector<int>& v1,const vector<int>& v2);


int main()
{
    // 1. 各ユーザごとに任意のn桁のビット列をランダム生成する

    int n;
    cout<<"ビット列の桁数:";
    cin>>n;
    cout<<endl;

    
    int num_users;
    cout << "参加人数:";
    cin >> num_users;
    cout << endl;


    std::vector<std::vector<int>> all_data;
    all_data.reserve(num_users); // メモリを予約

    // ユーザの数だけループ
    for(int i = 0; i < num_users; ++i) {
        all_data.push_back(GenerateRandomBitVector(n));
        
        std::cout << "User " << (i + 1) << " data:" << std::endl;
        PrintBitVector(all_data[i]);
    }

    // 2. 鍵生成
    // パラメータを設定
    const unsigned int degree = 8;
    const uint64_t modulus = 320417;

    // 多項式環のパラメータを生成
    const unsigned int cyclotomic_order = 2 * degree;
    NativeInteger rootOfUnity = RootOfUnity<NativeInteger>(cyclotomic_order, modulus);
    auto params = std::make_shared<ILNativeParams>(cyclotomic_order, modulus, rootOfUnity);

    std::vector<Poly> secret_keys(num_users);
    std::vector<Poly> public_keys(num_users);

    for (int i = 0; i < num_users; ++i) {
        std::cout << "Generating keys for user " << (i + 1) << "..." << std::endl;
        while (!KeyGen(degree, params, secret_keys[i], public_keys[i]));
    }

    // 合成秘密鍵
    Poly f_combined = secret_keys[0]; // 最初のユーザの鍵で初期化
    for (int i = 1; i < num_users; ++i) {
        f_combined = f_combined * secret_keys[i]; // 全員の秘密鍵を乗算
    }
    

    // 3. 1で生成したビット列の各桁について，暗号化する

    std::vector<std::vector<Poly>> all_ciphers;
    all_ciphers.reserve(num_users);

    for (int i = 0; i < num_users; ++i) {
        all_ciphers.push_back(EncryptBitVector(public_keys[i], all_data[i], degree, params));
    }

    // 4. n回XORを実行

    std::vector<Poly> c_seed;

for(int i = 0; i < n; i++){
        
        // 最初のユーザ (j=0) の暗号文で初期化
        Poly c_seed_i = all_ciphers[0][i];

        // 2人目 (j=1) から最後のユーザまで、全員の暗号文を加算 (XOR)
        for (int j = 1; j < num_users; ++j) {
            c_seed_i = EvaluateAdd(c_seed_i, all_ciphers[j][i]);
        }

        c_seed.push_back(c_seed_i);
    }

    // 5. 復号

    std::vector<int> c_seed_dec;

    for(int i=0;i<n;i++){
        int c_seed_i_dec = Decrypt(f_combined,c_seed[i]);
        c_seed_dec.push_back(c_seed_i_dec);

    }

    //6. 結果の検証

    std::cout << "\n--- Generated Group Seed (S_group) ---" << std::endl;
    for (long unsigned int i = 0; i < c_seed_dec.size(); ++i) {
        std::cout << c_seed_dec[i];
        if ((i + 1) % 32 == 0) std::cout << std::endl; // 見やすく改行
    }
    
    cout<<endl;
    
    // ... (ステップ6. 結果の検証 の続き) ...

    std::cout << "\n\n================================================" << std::endl;
    std::cout << " PHASE 2: High-speed data transmission (Demo)" << std::endl;
    std::cout << "================================================" << std::endl;

    
    int message_length;
    cout<<"送信するメッセージ長:";
    cin>>message_length;
    std::vector<int> M_original = GenerateRandomBitVector(message_length);
    std::cout << "Original Message (M):" << std::endl;
    PrintBitVector(M_original);


    // --- 送信側の処理 (例: ユーザ1) ---
    std::cout << "\n--- Sender (User 1) ---" << std::endl;
    
    // 2. フェーズ1のシード (c_seed_dec) から長いパッドを生成
    std::vector<int> pad_sender = GenerateLongPad(c_seed_dec, message_length);

    // 3. メッセージ M と パッドをXORして暗号文 C を生成
    std::vector<int> C_encrypted = XORvec(M_original, pad_sender);
    std::cout << "Encrypted (C = M xor Pad):" << std::endl;
    PrintBitVector(C_encrypted);


    // --- 受信側の処理 (例: ユーザ2) ---
    std::cout << "\n--- Receiver (User 2) ---" << std::endl;
    
    // 4. 受信側も、フェーズ1のシード (c_seed_dec) から *全く同じ* パッドをローカルで生成
    std::vector<int> pad_receiver = GenerateLongPad(c_seed_dec, message_length);

    // 5. 暗号文 C と パッドをXORして平文 M' を復号
    std::vector<int> M_decrypted = XORvec(C_encrypted, pad_receiver);
    std::cout << "Decrypted (M' = C xor Pad):" << std::endl;
    PrintBitVector(M_decrypted);


    // --- 最終検証 ---
    std::cout << "\n--- Verification ---" << std::endl;
    if (M_original == M_decrypted) {
        std::cout << "SUCCESS: Original Message and Decrypted Message match!" << std::endl;
    } else {
        std::cout << "FAILURE: Messages do not match." << std::endl;
    }






    return 0;


}

std::vector<int> GenerateRandomBitVector(int n){
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 1); // 0か1を均等に生成

    vector<int> bitVector;

    for (int i = 0; i < n; ++i) {
        bitVector.push_back(dis(gen));
    }
    return bitVector;
}


std::vector<Poly> EncryptBitVector(const Poly& pk, const std::vector<int>& bitVector, unsigned int degree, std::shared_ptr<ILNativeParams> params){
    vector<Poly> c_i;

    //bitVectorに入っている各ビットを暗号化する

    for(int bit:bitVector){
        c_i.push_back(Encrypt(pk,bit,degree,params));
    } 
    

    return c_i;
}

void PrintBitVector(vector<int>& bitVector){
    for(long unsigned int i=0;i<bitVector.size();i++){
        cout<<bitVector[i];
    }

    cout<<endl;
}

vector<int> GenerateLongPad(const vector<int>& seed,int len)
{
    seed_seq ssq(seed.begin(),seed.end());

    //共有のシードを使って乱数生成器を初期化
    mt19937 gen(ssq);

    //0か1を均等に生成
    uniform_int_distribution<> dis(0,1);

    //任意の長さのパッド生成
    vector<int> longpad;

    for(int i=0;i<len;i++){
        longpad.push_back(dis(gen));
    }

    return longpad;
}

vector<int> XORvec(const vector<int>& v1,const vector<int>& v2){
    //メッセージmとパッドpのXOR
    vector<int> result;
    size_t len = v1.size();

    for(size_t i=0;i<len;i++){
        result.push_back(v1[i]^v2[i]);
    }

    return result;
}