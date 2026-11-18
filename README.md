# sekka(雪華)— x64 PE 例外テーブル(.pdata)静的解析ツールキット

**sekka**は、64ビットPEイメージの例外テーブル(`.pdata` / `RUNTIME_FUNCTION`)とアンワインド情報(`UNWIND_INFO`)を静的に解析するPythonツールキットです。実行せず、ファイル(またはメモリダンプ)から例外処理のメタデータを読み、次のような問いに答えます。

- このアドレスはどの関数に属するのか(例外ハンドラ表引き)
- ある関数領域にアンワインド情報は存在するか
- この`.pdata`は壊れていないか(整合性検証)

雪華は「雪の結晶」の意。x86-64のアンワインド情報は、関数の境界を結晶のように規則正しく記録する静的構造です。

## 特徴

- **純Python・サードパーティ依存ゼロ**で動作(NumPyは後述の任意依存)
- `.pdata`ディレクトリが壊れている・欠けているイメージでも、**パターン走査で`RUNTIME_FUNCTION`候補を発掘**
- メモリキャプチャにも対応:`sekka -`からの`REGION`系ヘッダの自動除去に対応
- Python API(ライブラリ)とCLI(コマンド)の両面で使える

非破壊・非実行の静的解析ツールであり、例外ディレクトリが壊れたPEの復旧、クラッシュレポートのスタック逆算、プロファイラの関数境界抽出、CIでのlintなどに使えます。

## インストール

```console
pip install sekka
```

NumPyによる高速化を有効にする場合:

```console
pip install sekka[fast]
```

## コマンド

```console
python3 -m sekka.cli <command> <PEファイル> [options]
```

| コマンド | 内容 |
|---|---|
| `lookup` | アドレスから関数範囲・アンワインド情報の位置を検索 |
| `table` | `.pdata`ディレクトリの全エントリを一覧 |
| `handlers` | `.pdata`を走査し、例外ハンドラを持つ関数を一覧 |
| `validate` | `.pdata`の整合性検証(begin/end/unwindの妥当性・重複) |

### lookup: アドレスから関数表引き

```console
$ python3 -m sekka.cli lookup app.exe 0x140010020
0x140010020 → function [0x140010000, 0x140010080)  unwind @0x140020000
$ python3 -m sekka.cli lookup app.exe --scan 0x140010020
```

`--scan`を付けると、`.pdata`ディレクトリ自体が壊れている場合でもイメージ全体をパターン走査して該当エントリを探します。メモリキャプチャは`REGION:`行込みのテキストから入力できます:

```console
$ python3 -m sekka.cli lookup dump.txt --json
[{"query": "0x140010020", "begin": "0x140010000", "end": "0x140010080", "unwind_rva": "0x2000"}]
```

### handlers: 例外ハンドラ表

```console
$ python3 -m sekka.cli handlers app.exe --scan
scanned 1165 RUNTIME_FUNCTION candidates
  0x140001000..0x140001100  handler 0x00BEEF
```

`--scan`無しはディレクトリ読み込み、`--scan`は走査を表します。

### validate: 例外テーブル整合性検証

```console
$ python3 -m sekka.cli validate app.exe
ok
$ python3 -m sekka.cli validate stripped.exe
error: no .pdata; rerun with --scan
$ python3 -m sekka.cli validate corrupt.exe --scan
warning: entry #37: unwind RVA 0x26000 beyond image end (0x24000)
```

## Python API

```python
from sekka import pe, pdata

img = pe.load("app.exe")
entries = pdata.load_entries(img)          # 例外テーブル読み込み
fn = pdata.lookup(entries, 0x140010020)     # 表引き
cands = pdata.scan_candidates(img)         # 走査による候補発掘
```

`pe.load()`は、オンディスクのPE(`.exe`/`.dll`)と、先頭に`REGION:`行が付いたメモリキャプチャ形式の両方を受け付けます。

## 入力形式

- 通常のPEファイル(MZ/PEヘッダ + `.pdata`ディレクトリ)
- メモリキャプチャ(`REGION: <start> <size>`ヘッダ + 生ダンプ)は自動判別し、ヘッダ行を取り除いて処理します

## パフォーマンス(任意依存: NumPy)

`sekka[fast]`を導入すると、以下の処理がNumPyでベクトル化されます。未導入でも純Python実装が同じ結果を返します(ドロップイン置換)。

| 処理 | 高速化手法 |
|---|---|
| エントロピ計算・ゼロ比率 | `np.frombuffer` + `bincount`一括集計 |
| 例外テーブル読み込み | `frombuffer`で(N,3)行列化 → 無効エントリをマスク一括除外 |
| パターン走査候補抽出 | u4ビュー + スライス3枚で全オフセットを一括マスク → `flatnonzero`で列挙 |

走査ヒット後の個々の候補検証(`UNWIND_INFO`解読、RVA→オセット変換、関数範囲の上限判定)はデータ依存の分岐が多く、ベクトル化せず純Pythonのまま検証します。ハンドラ表引きは二分探索(O(log n))で、検索本数が多くない限り十分高速です。

## モジュール

| モジュール | 役割 |
|---|---|
| `sekka/pe.py` | PEローダ(ヘッダ解析・セクション・RVA⇔オセット変換) |
| `sekka/pdata.py` | 例外テーブルの読み込み・表引き・走査 |
| `sekka/unwind.py` | UNWIND_INFOの解析(プロローグ命令列の復号) |
| `sekka/state.py` | 走査候補の統計的評価(エントロピ・ゼロ比率による分類) |
| `sekka/fastpath.py` | NumPy実装(HAVE_NUMPYで自動切替、未導入なら純実装にfallback) |
| `sekka/cli.py` | コマンドラインフロントエンド |

## テスト

```console
$ python3 tests/test_sekka.py
```

合成PEイメージを動的に組み立てるため、外部フィクスチャは不要です。NumPyが導入された環境では高速実装と純実装の**等価性テスト**が自動的に走ります(未導入ではskip)。

## 制限

- x86-64のみ(chained unwind info は平坦化して扱います)
- 例外ディレクトリ破損時の走査はヒューリスティックであり、擬陽性(データ中の偶然の一致)を含みます
- 静的解析のみ。実行時の例外動作の再現は行いません

## ライセンス

Apache-2.0
