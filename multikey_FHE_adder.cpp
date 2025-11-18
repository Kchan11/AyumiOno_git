#include "openfhe.h"
#include <iostream>
#include <vector>
#include <random>
#include <memory>
#include "math/discretegaussiangenerator.h"

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




int main(int argc, char* argv[]) {
    // パラメータを設定
    //const unsigned int degree = 8;
    //const uint64_t modulus = 320609;
    const unsigned int degree = 2;
    const uint64_t modulus = 62921;


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

    cout<<f_combined<<endl;

    // =================================================================
    // 2. メッセージ「0」と「1」の暗号化
    // 3つの項で演算できるか？
    // =================================================================
    int m_zero = 0;
    int m_one = 1;
    int m_zero_2 = 0;

    // std::cout << "\nEncrypting m_zero=" << m_zero << " and m_one=" << m_one << "..." << std::endl;
    
    // それぞれ異なる鍵で暗号化
    Poly c_zero = Encrypt(h_zero, m_zero, degree, params);
    Poly c_one = Encrypt(h_one, m_one, degree, params);
    Poly c_zero_2 = Encrypt(h_zero,m_zero_2,degree,params);

    

    // =================================================================
    // 3. 同型演算
    // =================================================================
    std::cout << "Performing homomorphic operations..." << std::endl;
    Poly c_add = EvaluateAdd(c_zero, c_one);
    Poly c_add_result = EvaluateAdd(c_add,c_zero_2);

    Poly c_mult = EvaluateMult(c_zero, c_one);
    Poly c_mult_result = EvaluateMult(c_mult,c_zero_2);

    // (a+b) * c
    Poly c_mix_result = EvaluateMult(c_add,c_zero_2); 

    // =================================================================
    // 4. 復号
    // =================================================================
    std::cout << "Decrypting results..." << std::endl;
    int dec_add = Decrypt(f_combined, c_add_result);

    int dec_mult = Decrypt(f_combined, c_mult_result);
    int dec_mix = Decrypt(f_combined,c_mix_result);

    // =================================================================
    // 5. 結果の検証
    // =================================================================
    std::cout << "0+1+0 = ... " << dec_add << endl;
    std::cout << "0*1*0 = ... " << dec_mult << endl;
    std::cout << "(0+1)*0 = ... " << dec_mix<<endl;


    // 期待される結果 ( 1, 0, 0 ) と一致するかどうかを判定
    bool success = (dec_add == 1 && dec_mult == 0 && dec_mix == 0);

    if (success) {
        std::cout << "Final_Result: SUCCESS" << std::endl;
    } else {
        std::cout << "Final_Result: FAILURE" << std::endl;
    }
}
    


 

// ガウス分布に従う「小さい」係数の多項式を生成
Poly GenerateSmallPoly(unsigned int degree, std::shared_ptr<ILNativeParams> params) {
    DiscreteGaussianGeneratorImpl<NativeVector> dgg(0.4);
    //小さくすると，復号は成功しやすいが時間がかかる
    //安全性？
    Poly result(dgg, params, COEFFICIENT);
    return result;
}

// 鍵生成
bool KeyGen(unsigned int degree, std::shared_ptr<ILNativeParams> params, Poly& sk, Poly& pk) {
    Poly f_prime = GenerateSmallPoly(degree, params);

   /* std::cout << "--- Debug: f_prime (raw small poly) ---" << std::endl;
    std::cout << f_prime << std::endl; */

    Poly g = GenerateSmallPoly(degree, params);
    Poly f = f_prime * 2 + 1;

    
    // ★ 修正点: 逆元を計算する前に、まず存在するかどうかをチェックする ★
    // このチェックにより、ゼロ除算が原因のクラッシュを未然に防ぎます。
    if (!f.InverseExists()) {
        return false; // 逆元が存在しない場合は、失敗としてmain関数に通知し、再試行を促す
    }

        
    
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

