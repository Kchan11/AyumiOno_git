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


// ガウス分布に従う「小さい」係数の多項式を生成
Poly GenerateSmallPoly(unsigned int degree, std::shared_ptr<ILNativeParams> params) {
    DiscreteGaussianGeneratorImpl<NativeVector> dgg(1.0);
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
    return c1 + c2;
}

// 同型乗算
Poly EvaluateMult(const Poly& c1, const Poly& c2) {
    return c1 * c2;
}