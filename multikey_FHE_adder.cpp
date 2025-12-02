#include "openfhe.h"
#include <iostream>
#include <vector>
#include <random>
#include <memory>
#include "math/discretegaussiangenerator.h"


//加算器をつくる

// using宣言
using lbcrypto::NativeInteger;
using lbcrypto::ILNativeParams;
using lbcrypto::NativePoly;

using lbcrypto::DiscreteGaussianGeneratorImpl;
using lbcrypto::NativeVector;
using lbcrypto::RootOfUnity;

// このコードでは低レベルな多項式を直接扱うため、NativePolyをPolyとして定義
using Poly = NativePoly;

using namespace std;

// 関数のプロトタイプ宣言
Poly GenerateSmallPoly(unsigned int degree, std::shared_ptr<ILNativeParams> params);
bool KeyGen(unsigned int degree, std::shared_ptr<ILNativeParams> params, Poly& sk, Poly& pk);
Poly Encrypt(const Poly& pk, int message, unsigned int degree, std::shared_ptr<ILNativeParams> params);
int Decrypt(const Poly& sk_combined, const Poly& c);
Poly EvaluateAdd(const Poly& c1, const Poly& c2);
Poly EvaluateMult(const Poly& c1, const Poly& c2);
void PrintPolyContents(const Poly& poly, const std::string& message);
string GenerateRandomBinaryString(int len);
pair<Poly,Poly> FullAdder(const Poly& c_a,const Poly& c_b,const Poly& c_in);
string AddBinaryStrings(string a, string b);



int main(int argc, char* argv[]) {
    // パラメータを設定
    //const unsigned int degree = 64;
    //const uint64_t modulus = 1152921504606842753ULL;
    const unsigned int degree = 2;
    const uint64_t modulus = 1152921504606842753ULL;


    // 多項式環のパラメータを生成
    const unsigned int cyclotomic_order = 2 * degree;
    NativeInteger rootOfUnity = RootOfUnity<NativeInteger>(cyclotomic_order, modulus);
    auto params = std::make_shared<ILNativeParams>(cyclotomic_order, modulus, rootOfUnity);

    // =================================================================
    // 1. 鍵生成 (2ユーザ)
    // =================================================================
    Poly f_zero, h_zero, f_one, h_one;
    std::cout << "Generating keys for user 'zero'..." << std::endl;
    while (!KeyGen(degree, params, f_zero, h_zero));
    std::cout << "Generating keys for user 'one'..." << std::endl;
    while (!KeyGen(degree, params, f_one, h_one));

    // 合成秘密鍵
    Poly f_combined = f_zero * f_one;

    cout<<"f_combined: "<<f_combined<<endl;

    //ランダムな1~63ビットの整数を生成(繰り上がり込みで64ビット)
    string num_a,num_b;
    int len_a,len_b;

    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> len_dist(1, 3);

    len_a = len_dist(gen);
    len_b = len_dist(gen);

    num_a = GenerateRandomBinaryString(len_a);
    num_b = GenerateRandomBinaryString(len_b);

    cout << "numA:" << num_a<<endl;
    cout << "numB:" << num_b<<endl;

    size_t max_len = max(num_a.length(),num_b.length());

    //長い方のデータに合わせるために，短い方を0でパディングする

    string padded_a = num_a;
    string padded_b = num_b;
    while (padded_a.length() < max_len) padded_a = "0" + padded_a;
    while (padded_b.length() < max_len) padded_b = "0" + padded_b;

    int bits_len = static_cast<int>(max_len); //intにキャスト

    //ビットごとに暗号化
    vector<Poly> c_a(bits_len);
    vector<Poly> c_b(bits_len);

    std::cout << "Encrypting inputs..." << std::endl;
    for (int i = 0; i < bits_len; ++i) {
        // 下位ビットから処理するため、文字列の後ろからアクセス
        char char_a = padded_a[bits_len - 1 - i];
        char char_b = padded_b[bits_len - 1 - i];

        int val_a = char_a - '0';
        int val_b = char_b - '0';

        c_a[i] = Encrypt(h_zero, val_a, degree, params);
        c_b[i] = Encrypt(h_one,  val_b, degree, params);
    }


    //加算器の計算
    vector<Poly> c_sum(bits_len);

    Poly c_carry = Encrypt(h_zero,0,degree,params);

    for(int i=0;i<bits_len;i++){
        pair<Poly,Poly> result = FullAdder(c_a[i],c_b[i],c_carry);
        c_sum[i] = result.first;
        c_carry = result.second;
    }
    

    

    // =================================================================
    // 4. 復号
    // =================================================================
    std::cout << "Decrypting results..." << std::endl;
    string fhe_result_str = "";

    int overflow_bit = Decrypt(f_combined, c_carry);
    if (overflow_bit == 1) {
        fhe_result_str += "1";
    }

    // 各ビットの復号 (上位ビットから順に文字列に追加)
    for (int i = bits_len - 1; i >= 0; --i) {
        int bit = Decrypt(f_combined, c_sum[i]);
        fhe_result_str += std::to_string(bit);
    }

    // =================================================================
    // 5. 結果の検証
    // =================================================================
    std::cout << "FHE Result:  " << fhe_result_str << std::endl;

    

    string true_result_str = AddBinaryStrings(num_a,num_b);

    std::cout << "True Result:  " << true_result_str<<endl;

    size_t first_one = fhe_result_str.find('1');
    std::string fhe_trimmed = (first_one == std::string::npos) ? "0" : fhe_result_str.substr(first_one);
    
    size_t true_first_one = true_result_str.find('1');
    std::string true_trimmed = (true_first_one == std::string::npos) ? "0" : true_result_str.substr(true_first_one);

    if (fhe_trimmed == true_trimmed) {
        std::cout << "--> SUCCESS" << std::endl;
    } else {
        std::cout << "--> FAILURE" << std::endl;
        std::cout << "Debug: FHE raw  = " << fhe_result_str << std::endl;
        std::cout << "Debug: True raw = " << true_result_str << std::endl;
    }
}
    


 

// ガウス分布に従う「小さい」係数の多項式を生成
Poly GenerateSmallPoly(unsigned int degree, std::shared_ptr<ILNativeParams> params) {
    DiscreteGaussianGeneratorImpl<NativeVector> dgg(0.3);
    //小さくすると，復号は成功しやすいが時間がかかる
    //安全性？
    Poly result(dgg, params, COEFFICIENT);
    return result;
}

// 鍵生成
bool KeyGen(unsigned int degree, std::shared_ptr<ILNativeParams> params, Poly& sk, Poly& pk) {
    Poly f_prime = GenerateSmallPoly(degree, params);

   

    Poly g = GenerateSmallPoly(degree, params);
    Poly f = f_prime * 2 + 1;

    
    // ★ 修正点: 逆元を計算する前に、まず存在するかどうかをチェックする ★
    // このチェックにより、ゼロ除算が原因のクラッシュを未然に防ぎます。
    if (!f.InverseExists()) {
        return false; // 逆元が存在しない場合は、失敗としてmain関数に通知し、再試行を促す
    }

    //std::cout << "--- Debug: f_prime (raw small poly) ---" << std::endl;
    //std::cout << f_prime << std::endl; 

        
    
    // 逆元が存在することを確認した上で、計算を実行する
    try {
        f.SwitchFormat();
        g.SwitchFormat();
    
        Poly f_inv = f.MultiplicativeInverse();
        
        sk = f;
        pk = g * 2 * f_inv;
       
        return true; // 成功
    } catch (const std::exception& e) {
        // InverseExists()でチェック済みですが、念のためtry-catchも残します
        return false; // 予期せぬエラーで失敗
    }
}

// 暗号化
Poly Encrypt(const Poly& pk, int message, unsigned int degree, std::shared_ptr<ILNativeParams> params) {
    Poly s = GenerateSmallPoly(degree, params);
    Poly e = GenerateSmallPoly(degree, params);
    Poly m(params, COEFFICIENT, true);
    m[0] = message;
    s.SwitchFormat();
    e.SwitchFormat();
    m.SwitchFormat();
    Poly c = pk * s + e * 2 + m;
    
    return c;
}

// 復号
int Decrypt(const Poly& sk_combined, const Poly& c) {
    Poly mu = c * sk_combined;
    mu.SwitchFormat();
    auto params = mu.GetParams();
    NativeInteger constant_term = mu[0];
    int64_t result = constant_term.ConvertToInt();
    int64_t modulus_int = params->GetModulus().ConvertToInt();
    if (result > modulus_int / 2) {
        result -= modulus_int;
    }
    return (result % 2 + 2) % 2;
}

// 同型加算
Poly EvaluateAdd(const Poly& c1, const Poly& c2) {
    Poly result =  c1 + c2;
    
    return result;
}

// 同型乗算
Poly EvaluateMult(const Poly& c1, const Poly& c2) {
    Poly result =  c1 * c2;

    return result;
}


string GenerateRandomBinaryString(int len){
    std::string s = "";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> bit_dist(0, 1);

    for (int i = 0; i < len; ++i) {
        s += std::to_string(bit_dist(gen));
    }
    return s;
}



pair<Poly,Poly> FullAdder(const Poly& c_a,const Poly& c_b,const Poly& c_in){
    Poly c_sum_partial = EvaluateAdd(c_a, c_b);
    Poly c_sum = EvaluateAdd(c_sum_partial, c_in);
    
    Poly term1 = EvaluateAdd(c_a, c_in);
    Poly term2 = EvaluateAdd(c_b, c_in);
    Poly term3 = EvaluateMult(term1, term2);
    Poly c_carry_out = EvaluateAdd(term3, c_in);

    return {c_sum, c_carry_out};
}

string AddBinaryStrings(string a,string b){
    std::string result = "";
    int i = a.length() - 1;
    int j = b.length() - 1;
    int carry = 0;

    while (i >= 0 || j >= 0 || carry) {
        int sum = carry;
        if (i >= 0) sum += a[i--] - '0';
        if (j >= 0) sum += b[j--] - '0';
        carry = sum >> 1;
        result += std::to_string(sum & 1);
    }
    std::reverse(result.begin(), result.end());
    return result.empty() ? "0" : result;
}