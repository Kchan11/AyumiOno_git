#include "openfhe.h"
#include <iostream>
#include <vector>
#include <memory>
#include <algorithm> // For std::min

// using宣言
using lbcrypto::NativeInteger;
using lbcrypto::ILNativeParams;
using lbcrypto::NativePoly;

using Poly = NativePoly;
using namespace std;

// --- 関数のプロトタイプ宣言 ---
void ForceModReduce(Poly& poly, const NativeInteger& modulus);
void PrintPolyContents(const Poly& poly, const std::string& message);

// --- メイン関数 ---
int main() {
    // 1. パラメータを設定
    // (q-1)/m が整数になる組み合わせを選択 (17-1)/16 = 1
    const unsigned int degree = 8;
    const uint64_t modulus = 17;

    cout << "Test Parameters:" << endl;
    cout << " - Degree (N): " << 2 * degree << endl;
    cout << " - Modulus (q): " << modulus << endl;
    cout << "----------------------------------------" << endl;

    // 多項式環のパラメータを生成
    const unsigned int cyclotomic_order = 2 * degree;
    NativeInteger rootOfUnity = lbcrypto::RootOfUnity<NativeInteger>(cyclotomic_order, modulus);
    auto params = std::make_shared<ILNativeParams>(cyclotomic_order, modulus, rootOfUnity);

    // 2. 多項式を準備
    Poly p1(params, COEFFICIENT, true);
    Poly p2(params, COEFFICIENT, true);

    // modulus(17)を超えた結果になるように係数を設定
    p1[0] = 15;
    p2[0] = 10;
    
    p1.SwitchFormat();
    p2.SwitchFormat();

    
    Poly p_mult = p1 * p2;
    Poly p_add =  p1 + p2;

    PrintPolyContents(p_add,"Result(add):"); 
    PrintPolyContents(p_mult, "Result(Mult):");
    
    
    


    return 0;
}

// --- ヘルパー関数の実装 ---

/**
 * @brief Polyの全係数に対して、明示的に剰余計算を行う
 */
void ForceModReduce(Poly& poly, const NativeInteger& modulus) {
    if (poly.GetFormat() == EVALUATION) {
        poly.SwitchFormat();
    }
    for (size_t i = 0; i < poly.GetLength(); ++i) {
        poly[i] = poly[i].Mod(modulus);
    }
}

/**
 * @brief Polyの係数配列の中身をコンソールに表示する
 */
void PrintPolyContents(const Poly& poly, const std::string& message) {
    Poly temp = poly;
    if (temp.GetFormat() == EVALUATION) {
        temp.SwitchFormat();
    }
    
    cout << message << endl;
    cout << "  [ ";
    
    // 異なる型同士の比較エラーを防ぐため、型をsize_tに揃える
    size_t print_length = std::min((size_t)8, (size_t)temp.GetLength());
    for (size_t i = 0; i < print_length; ++i) {
        cout << temp[i] << " ";
    }
    cout << "... ]" << endl << endl;
}