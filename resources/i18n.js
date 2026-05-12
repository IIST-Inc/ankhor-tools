(function () {
  const STORAGE_KEY = "ankhor-tools-language";
  const DEFAULT_LANGUAGE = "en";

  const languageNames = {
    en: "English",
    "zh-TW": "繁體中文",
    ja: "日本語",
    fr: "Français",
  };

  const strings = {
    "Language": {
      "zh-TW": "語言",
      ja: "言語",
      fr: "Langue",
    },
    "Browser-Based Utilities": {
      "zh-TW": "瀏覽器工具",
      ja: "ブラウザベースのユーティリティ",
      fr: "Utilitaires dans le navigateur",
    },
    "Ankhor Tools": {
      "zh-TW": "Ankhor 工具",
      ja: "Ankhor ツール",
      fr: "Outils Ankhor",
    },
    "Public tools, product information, and integration guides for compatible IIST / Ankhor devices.": {
      "zh-TW": "適用於相容 IIST / Ankhor 裝置的公開工具、產品資訊與整合指南。",
      ja: "互換性のある IIST / Ankhor デバイス向けの公開ツール、製品情報、統合ガイドです。",
      fr: "Outils publics, informations produit et guides d'intégration pour les appareils IIST / Ankhor compatibles.",
    },
    "Tools and Guides": {
      "zh-TW": "工具與指南",
      ja: "ツールとガイド",
      fr: "Outils et guides",
    },
    "Select the product check page, integration guide, command reference, downloads area, or support contact page.": {
      "zh-TW": "選擇產品檢測頁、整合指南、命令參考、下載區或支援聯絡頁。",
      ja: "製品確認ページ、統合ガイド、コマンドリファレンス、ダウンロード、サポート連絡先を選択できます。",
      fr: "Sélectionnez la page de vérification produit, le guide d'intégration, la référence des commandes, les téléchargements ou la page de contact.",
    },
    "Product Test & Verification": {
      "zh-TW": "產品測試與驗證",
      ja: "製品テストと検証",
      fr: "Test et vérification du produit",
    },
    "Product Verification": {
      "zh-TW": "產品驗證",
      ja: "製品検証",
      fr: "Vérification du produit",
    },
    "Minimal product verification tool for compatible Ankhor devices.": {
      "zh-TW": "適用於相容 Ankhor 裝置的精簡產品驗證工具。",
      ja: "互換性のある Ankhor デバイス向けの最小限の製品検証ツールです。",
      fr: "Outil minimal de vérification produit pour les appareils Ankhor compatibles.",
    },
    "Connect to a compatible Ankhor device, confirm connection status, read device information, and request TRNG output.": {
      "zh-TW": "連線至相容的 Ankhor 裝置、確認連線狀態、讀取裝置資訊並請求 TRNG 輸出。",
      ja: "互換性のある Ankhor デバイスに接続し、接続状態、デバイス情報、TRNG 出力を確認します。",
      fr: "Connectez un appareil Ankhor compatible, confirmez l'état de connexion, lisez les informations de l'appareil et demandez une sortie TRNG.",
    },
    "Open verification tool": {
      "zh-TW": "開啟驗證工具",
      ja: "検証ツールを開く",
      fr: "Ouvrir l'outil de vérification",
    },
    "FIDO2 Test via WebAuthn.io": {
      "zh-TW": "透過 WebAuthn.io 測試 FIDO2",
      ja: "WebAuthn.io で FIDO2 をテスト",
      fr: "Test FIDO2 via WebAuthn.io",
    },
    "Open the external WebAuthn.io browser test site for FIDO2 registration and authentication trials.": {
      "zh-TW": "開啟外部 WebAuthn.io 瀏覽器測試網站，進行 FIDO2 註冊與驗證測試。",
      ja: "FIDO2 の登録および認証テスト用に、外部の WebAuthn.io ブラウザテストサイトを開きます。",
      fr: "Ouvrez le site externe WebAuthn.io pour tester l'enregistrement et l'authentification FIDO2.",
    },
    "Open external site": {
      "zh-TW": "開啟外部網站",
      ja: "外部サイトを開く",
      fr: "Ouvrir le site externe",
    },
    "Scenario & Command References": {
      "zh-TW": "情境與命令參考",
      ja: "シナリオとコマンドリファレンス",
      fr: "Scénarios et référence des commandes",
    },
    "What Can I Do With Ankhor Key Plus?": {
      "zh-TW": "Ankhor Key Plus 可以做什麼？",
      ja: "Ankhor Key Plus で何ができますか？",
      fr: "Que puis-je faire avec Ankhor Key Plus ?",
    },
    "Browse practical application scenarios and see which Ankhor functions apply to database credentials, API keys, OTP, signing, encryption, local secrets, and device trust workflows.": {
      "zh-TW": "瀏覽實際應用情境，了解哪些 Ankhor 功能適用於資料庫憑證、API 金鑰、OTP、簽章、加密、本機機密與裝置信任流程。",
      ja: "実用的なアプリケーションシナリオを確認し、データベース認証情報、API キー、OTP、署名、暗号化、ローカルシークレット、デバイス信頼ワークフローに対応する Ankhor 機能を確認します。",
      fr: "Parcourez des scénarios pratiques et voyez quelles fonctions Ankhor s'appliquent aux identifiants de base de données, clés API, OTP, signature, chiffrement, secrets locaux et workflows de confiance.",
    },
    "View scenarios": {
      "zh-TW": "查看情境",
      ja: "シナリオを見る",
      fr: "Voir les scénarios",
    },
    "Command Reference": {
      "zh-TW": "命令參考",
      ja: "コマンドリファレンス",
      fr: "Référence des commandes",
    },
    "Review the CLI/API command families for connection, modes, activation, API key storage, password storage, OTP, BYO encryption, signing, pairing, and local secret storage.": {
      "zh-TW": "查看連線、模式、啟用、API 金鑰儲存、密碼儲存、OTP、BYO 加密、簽章、配對與本機機密儲存的 CLI/API 命令群組。",
      ja: "接続、モード、アクティベーション、API キー保存、パスワード保存、OTP、BYO 暗号化、署名、ペアリング、ローカルシークレット保存の CLI/API コマンド群を確認します。",
      fr: "Consultez les familles de commandes CLI/API pour connexion, modes, activation, stockage de clés API, mots de passe, OTP, chiffrement BYO, signature, appairage et secrets locaux.",
    },
    "Open reference": {
      "zh-TW": "開啟參考",
      ja: "リファレンスを開く",
      fr: "Ouvrir la référence",
    },
    "Downloads & Contact": {
      "zh-TW": "下載與聯絡",
      ja: "ダウンロードと連絡先",
      fr: "Téléchargements et contact",
    },
    "Downloads": {
      "zh-TW": "下載",
      ja: "ダウンロード",
      fr: "Téléchargements",
    },
    "Desktop software and packaged tools for password, key, credential, and device management. Consumer-style tools will be posted here when available.": {
      "zh-TW": "用於密碼、金鑰、憑證與裝置管理的桌面軟體與封裝工具。消費者型工具可用時會發布於此。",
      ja: "パスワード、キー、認証情報、デバイス管理向けのデスクトップソフトウェアとパッケージツールです。一般ユーザー向けツールは準備ができ次第ここに掲載します。",
      fr: "Logiciels de bureau et outils packagés pour la gestion des mots de passe, clés, identifiants et appareils. Les outils grand public seront publiés ici lorsqu'ils seront disponibles.",
    },
    "View downloads": {
      "zh-TW": "查看下載",
      ja: "ダウンロードを見る",
      fr: "Voir les téléchargements",
    },
    "Contact IIST": {
      "zh-TW": "聯絡 IIST",
      ja: "IIST に連絡",
      fr: "Contacter IIST",
    },
    "Request integration support, OEM software, custom workflows, provisioning scripts, or a custom version for your product.": {
      "zh-TW": "申請整合支援、OEM 軟體、自訂工作流程、佈建腳本，或產品專用版本。",
      ja: "統合サポート、OEM ソフトウェア、カスタムワークフロー、プロビジョニングスクリプト、製品向けカスタム版を依頼できます。",
      fr: "Demandez un support d'intégration, un logiciel OEM, des workflows personnalisés, des scripts de provisionnement ou une version adaptée à votre produit.",
    },
    "Contact support": {
      "zh-TW": "聯絡支援",
      ja: "サポートに連絡",
      fr: "Contacter le support",
    },
    "Back to Ankhor Tools": {
      "zh-TW": "返回 Ankhor 工具",
      ja: "Ankhor ツールに戻る",
      fr: "Retour aux outils Ankhor",
    },
    "Application Guide": {
      "zh-TW": "應用指南",
      ja: "アプリケーションガイド",
      fr: "Guide d'application",
    },
    "Choose your use case. Each scenario shows the Ankhor function area, suggested commands, integration idea, and where IIST can provide implementation support.": {
      "zh-TW": "選擇您的使用情境。每個情境都會顯示 Ankhor 功能領域、建議命令、整合想法，以及 IIST 可提供實作支援的部分。",
      ja: "ユースケースを選択してください。各シナリオでは Ankhor の機能領域、推奨コマンド、統合案、IIST が実装支援できる範囲を示します。",
      fr: "Choisissez votre cas d'utilisation. Chaque scénario présente la zone fonctionnelle Ankhor, les commandes suggérées, l'idée d'intégration et le support que IIST peut fournir.",
    },
    "Overview": {
      "zh-TW": "概覽",
      ja: "概要",
      fr: "Vue d'ensemble",
    },
    "Ankhor Key Plus provides a fixed set of hardware-rooted application security functions. It is not an unlimited custom firmware product by default. Users can use the provided CLI/API functions directly, or request IIST integration support for production deployment.": {
      "zh-TW": "Ankhor Key Plus 提供一組固定的硬體根信任應用安全功能。預設並不是無限制的客製韌體產品。使用者可以直接使用所提供的 CLI/API 功能，或向 IIST 申請正式部署的整合支援。",
      ja: "Ankhor Key Plus は、ハードウェアを信頼の根とする固定のアプリケーションセキュリティ機能を提供します。標準では無制限のカスタムファームウェア製品ではありません。ユーザーは提供される CLI/API 機能を直接使用するか、本番導入に向けた IIST の統合サポートを依頼できます。",
      fr: "Ankhor Key Plus fournit un ensemble fixe de fonctions de sécurité applicative ancrées dans le matériel. Ce n'est pas, par défaut, un produit à firmware personnalisé illimité. Les utilisateurs peuvent utiliser directement les fonctions CLI/API fournies ou demander un support d'intégration IIST pour le déploiement en production.",
    },
    "Need this implemented in your product?": {
      "zh-TW": "需要在您的產品中實作嗎？",
      ja: "これを製品に実装する必要がありますか？",
      fr: "Besoin de l'implémenter dans votre produit ?",
    },
    "Contact IIST for integration support, provisioning scripts, user-specific demos, or production workflow design.": {
      "zh-TW": "請聯絡 IIST 以取得整合支援、佈建腳本、使用者專屬示範或正式產品流程設計。",
      ja: "統合サポート、プロビジョニングスクリプト、ユーザー別デモ、本番ワークフロー設計については IIST にご連絡ください。",
      fr: "Contactez IIST pour le support d'intégration, les scripts de provisionnement, les démonstrations spécifiques ou la conception de workflows de production.",
    },
    "Common Preparation": {
      "zh-TW": "共通準備",
      ja: "共通準備",
      fr: "Préparation commune",
    },
    "Many protected operations require the same setup flow. Scenario sections focus on the business function commands, while mode selection and activation are common preparation steps.": {
      "zh-TW": "許多受保護操作需要相同的設定流程。情境章節聚焦於業務功能命令，而模式選擇與啟用是共通準備步驟。",
      ja: "多くの保護された操作では同じセットアップ手順が必要です。シナリオセクションでは業務機能コマンドに焦点を当て、モード選択とアクティベーションは共通準備手順として扱います。",
      fr: "De nombreuses opérations protégées nécessitent le même flux de configuration. Les scénarios se concentrent sur les commandes métier, tandis que la sélection du mode et l'activation sont des étapes communes.",
    },
    "First-time provisioning only:": {
      "zh-TW": "僅首次佈建：",
      ja: "初回プロビジョニングのみ:",
      fr: "Provisionnement initial uniquement :",
    },
    "Useful state checks:": {
      "zh-TW": "實用狀態檢查：",
      ja: "便利な状態確認:",
      fr: "Contrôles d'état utiles :",
    },
    "Cleanup:": {
      "zh-TW": "清理：",
      ja: "クリーンアップ:",
      fr: "Nettoyage :",
    },
    "Scenario Visual Guide": {
      "zh-TW": "情境視覺指南",
      ja: "シナリオのビジュアルガイド",
      fr: "Guide visuel des scénarios",
    },
    "These placeholder illustrations group the cookbook into practical integration areas. They are safe to replace later with detailed product diagrams.": {
      "zh-TW": "這些佔位插圖將 cookbook 分組為實際整合領域，之後可安全替換為詳細產品圖。",
      ja: "これらのプレースホルダー図は、クックブックを実用的な統合領域に分類しています。後で詳細な製品図に置き換えられます。",
      fr: "Ces illustrations provisoires regroupent le guide en domaines d'intégration pratiques. Elles pourront être remplacées plus tard par des schémas produit détaillés.",
    },
    "Credentials and OTP": {
      "zh-TW": "憑證與 OTP",
      ja: "認証情報と OTP",
      fr: "Identifiants et OTP",
    },
    "Database passwords, cloud API keys, and hardware-protected OTP records.": {
      "zh-TW": "資料庫密碼、雲端 API 金鑰，以及受硬體保護的 OTP 紀錄。",
      ja: "データベースパスワード、クラウド API キー、ハードウェア保護された OTP レコード。",
      fr: "Mots de passe de base de données, clés API cloud et enregistrements OTP protégés par le matériel.",
    },
    "Local Data Protection": {
      "zh-TW": "本機資料保護",
      ja: "ローカルデータ保護",
      fr: "Protection des données locales",
    },
    "Configuration encryption, database key wrapping, device-bound data, and local secrets.": {
      "zh-TW": "設定加密、資料庫金鑰包裝、裝置綁定資料與本機機密。",
      ja: "設定の暗号化、データベースキーのラッピング、デバイスに紐づくデータ、ローカルシークレット。",
      fr: "Chiffrement de configuration, encapsulation de clés de base de données, données liées à l'appareil et secrets locaux.",
    },
    "Signing and Verification": {
      "zh-TW": "簽章與驗證",
      ja: "署名と検証",
      fr: "Signature et vérification",
    },
    "Telemetry, logs, AI output, content authenticity signing support, and local verification.": {
      "zh-TW": "遙測、日誌、AI 輸出、內容真實性簽章支援與本機驗證。",
      ja: "テレメトリ、ログ、AI 出力、コンテンツ真正性署名サポート、ローカル検証。",
      fr: "Télémétrie, journaux, sorties IA, support de signature d'authenticité de contenu et vérification locale.",
    },
    "Pairing and Payloads": {
      "zh-TW": "配對與酬載",
      ja: "ペアリングとペイロード",
      fr: "Appairage et charges utiles",
    },
    "Gateway-to-sensor pairing and encrypted communication between paired devices.": {
      "zh-TW": "閘道器與感測器配對，以及配對裝置間的加密通訊。",
      ja: "ゲートウェイとセンサーのペアリング、およびペアリング済みデバイス間の暗号化通信。",
      fr: "Appairage passerelle-capteur et communication chiffrée entre appareils appairés.",
    },
    "Lifecycle and Support": {
      "zh-TW": "生命週期與支援",
      ja: "ライフサイクルとサポート",
      fr: "Cycle de vie et support",
    },
    "Mode control, activation, deletion, reset, device information, TRNG, and debug workflows.": {
      "zh-TW": "模式控制、啟用、刪除、重設、裝置資訊、TRNG 與除錯流程。",
      ja: "モード制御、アクティベーション、削除、リセット、デバイス情報、TRNG、デバッグワークフロー。",
      fr: "Contrôle de mode, activation, suppression, réinitialisation, informations appareil, TRNG et workflows de débogage.",
    },
    "Scenario Cookbook": {
      "zh-TW": "情境 Cookbook",
      ja: "シナリオクックブック",
      fr: "Guide de scénarios",
    },
    "Each entry starts from a user goal and maps it to concrete Ankhor function areas.": {
      "zh-TW": "每個項目都從使用者目標出發，對應到具體 Ankhor 功能領域。",
      ja: "各項目はユーザーの目的から始まり、具体的な Ankhor 機能領域に対応付けます。",
      fr: "Chaque entrée part d'un objectif utilisateur et le relie à des zones fonctionnelles Ankhor concrètes.",
    },
    "Function area": { "zh-TW": "功能領域", ja: "機能領域", fr: "Zone fonctionnelle" },
    "Important": { "zh-TW": "重要", ja: "重要", fr: "Important" },
    "Problem": { "zh-TW": "問題", ja: "課題", fr: "Problème" },
    "Typical deployment": { "zh-TW": "典型部署", ja: "一般的な導入", fr: "Déploiement typique" },
    "Use these functions": { "zh-TW": "使用這些功能", ja: "使用する機能", fr: "Utilisez ces fonctions" },
    "Suggested integration": { "zh-TW": "建議整合", ja: "推奨統合", fr: "Intégration suggérée" },
    "User work": { "zh-TW": "使用者工作", ja: "ユーザー側の作業", fr: "Travail utilisateur" },
    "IIST optional service": { "zh-TW": "IIST 選配服務", ja: "IIST オプションサービス", fr: "Service optionnel IIST" },
    "I want users to log in without passwords": { "zh-TW": "我想讓使用者不需密碼即可登入", ja: "ユーザーがパスワードなしでログインできるようにしたい", fr: "Je veux que les utilisateurs se connectent sans mot de passe" },
    "I want to protect database passwords on a gateway or server": { "zh-TW": "我想保護閘道器或伺服器上的資料庫密碼", ja: "ゲートウェイまたはサーバー上のデータベースパスワードを保護したい", fr: "Je veux protéger les mots de passe de base de données sur une passerelle ou un serveur" },
    "I want to protect cloud API keys": { "zh-TW": "我想保護雲端 API 金鑰", ja: "クラウド API キーを保護したい", fr: "Je veux protéger les clés API cloud" },
    "I want hardware-protected OTP/TOTP codes": { "zh-TW": "我想要受硬體保護的 OTP/TOTP 代碼", ja: "ハードウェア保護された OTP/TOTP コードがほしい", fr: "Je veux des codes OTP/TOTP protégés par le matériel" },
    "I want to encrypt local configuration data": { "zh-TW": "我想加密本機設定資料", ja: "ローカル設定データを暗号化したい", fr: "Je veux chiffrer les données de configuration locales" },
    "I want to protect a local SQLite database or local database key": { "zh-TW": "我想保護本機 SQLite 資料庫或本機資料庫金鑰", ja: "ローカル SQLite データベースまたはローカルデータベースキーを保護したい", fr: "Je veux protéger une base SQLite locale ou une clé de base locale" },
    "I want to sign telemetry data": { "zh-TW": "我想簽署遙測資料", ja: "テレメトリデータに署名したい", fr: "Je veux signer les données de télémétrie" },
    "I want to sign system logs": { "zh-TW": "我想簽署系統日誌", ja: "システムログに署名したい", fr: "Je veux signer les journaux système" },
    "I want to sign AI-generated outputs": { "zh-TW": "我想簽署 AI 產生的輸出", ja: "AI 生成出力に署名したい", fr: "Je veux signer les sorties générées par l'IA" },
    "I want to support C2PA or content authenticity": { "zh-TW": "我想支援 C2PA 或內容真實性", ja: "C2PA またはコンテンツ真正性をサポートしたい", fr: "Je veux prendre en charge C2PA ou l'authenticité du contenu" },
    "I want secure pairing between a gateway and a sensor": { "zh-TW": "我想在閘道器與感測器之間建立安全配對", ja: "ゲートウェイとセンサー間で安全なペアリングを行いたい", fr: "Je veux un appairage sécurisé entre une passerelle et un capteur" },
    "I want encrypted communication between paired devices": { "zh-TW": "我想在配對裝置之間進行加密通訊", ja: "ペアリング済みデバイス間で暗号化通信を行いたい", fr: "Je veux une communication chiffrée entre appareils appairés" },
    "I want data to be readable only on the original device": { "zh-TW": "我想讓資料只能在原始裝置上讀取", ja: "データを元のデバイスでのみ読めるようにしたい", fr: "Je veux que les données ne soient lisibles que sur l'appareil d'origine" },
    "I want to store small local secret blobs": { "zh-TW": "我想儲存小型本機機密資料區塊", ja: "小さなローカルシークレット blob を保存したい", fr: "Je veux stocker de petits blocs de secrets locaux" },
    "I want to securely remove old secrets": { "zh-TW": "我想安全移除舊機密", ja: "古いシークレットを安全に削除したい", fr: "Je veux supprimer en sécurité les anciens secrets" },
    "I want deterministic key derivation from an application seed": { "zh-TW": "我想從應用程式種子進行決定性金鑰衍生", ja: "アプリケーションシードから決定論的にキーを導出したい", fr: "Je veux une dérivation déterministe de clé à partir d'une graine applicative" },
    "I want to verify signatures locally": { "zh-TW": "我想在本機驗證簽章", ja: "署名をローカルで検証したい", fr: "Je veux vérifier les signatures localement" },
    "I want separate trust domains for different applications": { "zh-TW": "我想為不同應用程式分離信任網域", ja: "異なるアプリケーションに別々の信頼ドメインを持たせたい", fr: "Je veux des domaines de confiance séparés pour différentes applications" },
    "I want operator-controlled secure actions": { "zh-TW": "我想要由操作員控制的安全動作", ja: "オペレーター制御の安全な操作を行いたい", fr: "Je veux des actions sécurisées contrôlées par l'opérateur" },
    "I want to validate hardware random number generation": { "zh-TW": "我想驗證硬體亂數產生", ja: "ハードウェア乱数生成を検証したい", fr: "Je veux valider la génération matérielle de nombres aléatoires" },
    "I want to inspect device identity and firmware information": { "zh-TW": "我想檢查裝置身分與韌體資訊", ja: "デバイス ID とファームウェア情報を確認したい", fr: "Je veux inspecter l'identité de l'appareil et les informations firmware" },
    "I want to reset one application without wiping everything": { "zh-TW": "我想重設單一應用而不清除全部資料", ja: "すべてを消去せずに 1 つのアプリケーションをリセットしたい", fr: "Je veux réinitialiser une application sans tout effacer" },
    "I want to wipe the device for lab reset or redeployment": { "zh-TW": "我想清除裝置以進行實驗室重設或重新部署", ja: "ラボリセットまたは再配備のためにデバイスを消去したい", fr: "Je veux effacer l'appareil pour un reset de laboratoire ou un redéploiement" },
    "I want low-level debug access during integration": { "zh-TW": "我想在整合期間取得低階除錯存取", ja: "統合中に低レベルのデバッグアクセスがほしい", fr: "Je veux un accès de débogage bas niveau pendant l'intégration" },
    "Function Map": { "zh-TW": "功能對照表", ja: "機能マップ", fr: "Carte des fonctions" },
    "User Goal": { "zh-TW": "使用者目標", ja: "ユーザー目標", fr: "Objectif utilisateur" },
    "Suggested Ankhor Function Area": { "zh-TW": "建議 Ankhor 功能領域", ja: "推奨 Ankhor 機能領域", fr: "Zone fonctionnelle Ankhor suggérée" },
    "Passwordless login": { "zh-TW": "無密碼登入", ja: "パスワードレスログイン", fr: "Connexion sans mot de passe" },
    "FIDO2 authentication use case, no public test tool": { "zh-TW": "FIDO2 驗證使用情境，無公開測試工具", ja: "FIDO2 認証ユースケース、公開テストツールなし", fr: "Cas d'utilisation d'authentification FIDO2, sans outil de test public" },
    "Protect database password": { "zh-TW": "保護資料庫密碼", ja: "データベースパスワードの保護", fr: "Protéger le mot de passe de base de données" },
    "Protect API token": { "zh-TW": "保護 API 權杖", ja: "API トークンの保護", fr: "Protéger le jeton API" },
    "Generate OTP code": { "zh-TW": "產生 OTP 代碼", ja: "OTP コードの生成", fr: "Générer un code OTP" },
    "Encrypt local config": { "zh-TW": "加密本機設定", ja: "ローカル設定の暗号化", fr: "Chiffrer la configuration locale" },
    "Protect local database key": { "zh-TW": "保護本機資料庫金鑰", ja: "ローカルデータベースキーの保護", fr: "Protéger la clé de base locale" },
    "Sign telemetry": { "zh-TW": "簽署遙測資料", ja: "テレメトリへの署名", fr: "Signer la télémétrie" },
    "Sign logs": { "zh-TW": "簽署日誌", ja: "ログへの署名", fr: "Signer les journaux" },
    "Sign AI output": { "zh-TW": "簽署 AI 輸出", ja: "AI 出力への署名", fr: "Signer la sortie IA" },
    "Support content authenticity signing": { "zh-TW": "支援內容真實性簽章", ja: "コンテンツ真正性署名のサポート", fr: "Prendre en charge la signature d'authenticité du contenu" },
    "Pair gateway and sensor": { "zh-TW": "配對閘道器與感測器", ja: "ゲートウェイとセンサーのペアリング", fr: "Appairer passerelle et capteur" },
    "Encrypt paired-device payload": { "zh-TW": "加密配對裝置酬載", ja: "ペアリング済みデバイスのペイロード暗号化", fr: "Chiffrer la charge utile d'appareils appairés" },
    "Device-bound data protection": { "zh-TW": "裝置綁定資料保護", ja: "デバイス紐づけデータ保護", fr: "Protection des données liées à l'appareil" },
    "Store local secret blob": { "zh-TW": "儲存本機機密資料區塊", ja: "ローカルシークレット blob の保存", fr: "Stocker un bloc de secret local" },
    "Remove old secrets": { "zh-TW": "移除舊機密", ja: "古いシークレットの削除", fr: "Supprimer les anciens secrets" },
    "Deterministic key derivation": { "zh-TW": "決定性金鑰衍生", ja: "決定論的キー導出", fr: "Dérivation déterministe de clé" },
    "Verify signatures": { "zh-TW": "驗證簽章", ja: "署名の検証", fr: "Vérifier les signatures" },
    "Separate trust domains": { "zh-TW": "分離信任網域", ja: "信頼ドメインの分離", fr: "Séparer les domaines de confiance" },
    "Operator-controlled secure action": { "zh-TW": "操作員控制的安全動作", ja: "オペレーター制御の安全操作", fr: "Action sécurisée contrôlée par l'opérateur" },
    "Validate random source": { "zh-TW": "驗證亂數來源", ja: "乱数ソースの検証", fr: "Valider la source aléatoire" },
    "Device identity check": { "zh-TW": "裝置身分檢查", ja: "デバイス ID 確認", fr: "Contrôle d'identité de l'appareil" },
    "Reset one app": { "zh-TW": "重設單一應用", ja: "1 つのアプリをリセット", fr: "Réinitialiser une application" },
    "Wipe device": { "zh-TW": "清除裝置", ja: "デバイスの消去", fr: "Effacer l'appareil" },
    "Debug integration": { "zh-TW": "整合除錯", ja: "統合デバッグ", fr: "Déboguer l'intégration" },
    "BYO edge encryption": { "zh-TW": "BYO edge 加密", ja: "BYO edge 暗号化", fr: "Chiffrement BYO edge" },
    "BYO signing": { "zh-TW": "BYO 簽章", ja: "BYO 署名", fr: "Signature BYO" },
    "BYO pairing": { "zh-TW": "BYO 配對", ja: "BYO ペアリング", fr: "Appairage BYO" },
    "BYO shared-slot encryption": { "zh-TW": "BYO 共用槽加密", ja: "BYO 共有スロット暗号化", fr: "Chiffrement BYO par emplacement partagé" },
    "BYO local secret storage": { "zh-TW": "BYO 本機機密儲存", ja: "BYO ローカルシークレット保存", fr: "Stockage BYO de secrets locaux" },
    "AKM, PM, OTP, BYO delete functions": { "zh-TW": "AKM、PM、OTP、BYO 刪除功能", ja: "AKM、PM、OTP、BYO 削除機能", fr: "Fonctions de suppression AKM, PM, OTP, BYO" },
    "BYO get-key": { "zh-TW": "BYO get-key", ja: "BYO get-key", fr: "BYO get-key" },
    "BYO verify": { "zh-TW": "BYO verify", ja: "BYO verify", fr: "BYO verify" },
    "Mode control": { "zh-TW": "模式控制", ja: "モード制御", fr: "Contrôle du mode" },
    "PIN and activation": { "zh-TW": "PIN 與啟用", ja: "PIN とアクティベーション", fr: "PIN et activation" },
    "IIST integration services": { "zh-TW": "IIST 整合服務", ja: "IIST 統合サービス", fr: "Services d'intégration IIST" },
    "Linux integration": { "zh-TW": "Linux 整合", ja: "Linux 統合", fr: "Intégration Linux" },
    "OpenWrt integration": { "zh-TW": "OpenWrt 整合", ja: "OpenWrt 統合", fr: "Intégration OpenWrt" },
    "Python integration examples": { "zh-TW": "Python 整合範例", ja: "Python 統合例", fr: "Exemples d'intégration Python" },
    "C integration examples": { "zh-TW": "C 整合範例", ja: "C 統合例", fr: "Exemples d'intégration C" },
    "Deprovisioning scripts": { "zh-TW": "解除佈建腳本", ja: "デプロビジョニングスクリプト", fr: "Scripts de déprovisionnement" },
    "Gateway integration": { "zh-TW": "閘道器整合", ja: "ゲートウェイ統合", fr: "Intégration passerelle" },
    "Device pairing workflow design": { "zh-TW": "裝置配對流程設計", ja: "デバイスペアリングのワークフロー設計", fr: "Conception de workflow d'appairage d'appareils" },
    "Content authenticity signing adapter": { "zh-TW": "內容真實性簽章轉接器", ja: "コンテンツ真正性署名アダプター", fr: "Adaptateur de signature d'authenticité du contenu" },
    "Signed log or signed telemetry workflow": { "zh-TW": "簽署日誌或簽署遙測流程", ja: "署名付きログまたは署名付きテレメトリのワークフロー", fr: "Workflow de journaux ou télémétrie signés" },
    "API key and database credential protection workflow": { "zh-TW": "API 金鑰與資料庫憑證保護流程", ja: "API キーとデータベース認証情報保護のワークフロー", fr: "Workflow de protection des clés API et identifiants de base de données" },
    "User-specific demo and validation package": { "zh-TW": "使用者專屬示範與驗證套件", ja: "ユーザー別デモおよび検証パッケージ", fr: "Package de démonstration et validation spécifique utilisateur" },
    "OEM-branded desktop tools": { "zh-TW": "OEM 品牌桌面工具", ja: "OEM ブランドのデスクトップツール", fr: "Outils de bureau à marque OEM" },
    "Custom software for user deployment": { "zh-TW": "使用者部署專用客製軟體", ja: "ユーザー展開向けカスタムソフトウェア", fr: "Logiciel personnalisé pour le déploiement utilisateur" },
    "Commercial Integration Note": { "zh-TW": "商業整合說明", ja: "商用統合に関する注記", fr: "Note d'intégration commerciale" },
    "Need this implemented in your product? Contact IIST for integration support.": {
      "zh-TW": "需要在您的產品中實作嗎？請聯絡 IIST 取得整合支援。",
      ja: "製品への実装が必要ですか？統合サポートについて IIST にご連絡ください。",
      fr: "Besoin de l'implémenter dans votre produit ? Contactez IIST pour le support d'intégration.",
    },
    "Engineer Reference": { "zh-TW": "工程參考", ja: "エンジニア向けリファレンス", fr: "Référence ingénieur" },
    "Shared command families for Ankhor / SASE CLI and API integrations.": {
      "zh-TW": "Ankhor / SASE CLI 與 API 整合共用命令群組。",
      ja: "Ankhor / SASE CLI および API 統合で共有されるコマンド群です。",
      fr: "Familles de commandes communes pour les intégrations CLI et API Ankhor / SASE.",
    },
    "Most user integrations should start from the scenario cookbook.": {
      "zh-TW": "大多數使用者整合應從情境 cookbook 開始。",
      ja: "ほとんどのユーザー統合はシナリオクックブックから始めるべきです。",
      fr: "La plupart des intégrations utilisateur devraient commencer par le guide de scénarios.",
    },
    "This page is for engineers who need command-level details.": {
      "zh-TW": "本頁提供給需要命令層級細節的工程師。",
      ja: "このページはコマンドレベルの詳細が必要なエンジニア向けです。",
      fr: "Cette page s'adresse aux ingénieurs qui ont besoin de détails au niveau des commandes.",
    },
    "Connection and Session": { "zh-TW": "連線與工作階段", ja: "接続とセッション", fr: "Connexion et session" },
    "Mode and Application Control": { "zh-TW": "模式與應用程式控制", ja: "モードとアプリケーション制御", fr: "Contrôle du mode et de l'application" },
    "API Key Manager / AKM": { "zh-TW": "API 金鑰管理器 / AKM", ja: "API キーマネージャー / AKM", fr: "Gestionnaire de clés API / AKM" },
    "Password / Credential Manager / PM": { "zh-TW": "密碼 / 憑證管理器 / PM", ja: "パスワード / 認証情報マネージャー / PM", fr: "Gestionnaire de mots de passe / identifiants / PM" },
    "OTP Manager": { "zh-TW": "OTP 管理器", ja: "OTP マネージャー", fr: "Gestionnaire OTP" },
    "BYO Shared-Key Slots / Pairing": { "zh-TW": "BYO 共用金鑰槽 / 配對", ja: "BYO 共有キースロット / ペアリング", fr: "Emplacements à clé partagée BYO / appairage" },
    "BYO Shared-Slot Encryption": { "zh-TW": "BYO 共用槽加密", ja: "BYO 共有スロット暗号化", fr: "Chiffrement BYO par emplacement partagé" },
    "BYO Edge-Key Encryption": { "zh-TW": "BYO Edge-Key 加密", ja: "BYO Edge-Key 暗号化", fr: "Chiffrement BYO Edge-Key" },
    "BYO Local Secret Storage": { "zh-TW": "BYO 本機機密儲存", ja: "BYO ローカルシークレット保存", fr: "Stockage BYO de secrets locaux" },
    "BYO Signing and Verification": { "zh-TW": "BYO 簽章與驗證", ja: "BYO 署名と検証", fr: "Signature et vérification BYO" },
    "Open the scenario cookbook": { "zh-TW": "開啟情境 cookbook", ja: "シナリオクックブックを開く", fr: "Ouvrir le guide de scénarios" },
    "User Software": { "zh-TW": "使用者軟體", ja: "ユーザーソフトウェア", fr: "Logiciel utilisateur" },
    "Packaged desktop tools and user software will be posted here when available.": {
      "zh-TW": "封裝桌面工具與使用者軟體可用時會發布於此。",
      ja: "パッケージ化されたデスクトップツールとユーザーソフトウェアは、利用可能になり次第ここに掲載されます。",
      fr: "Les outils de bureau packagés et logiciels utilisateur seront publiés ici lorsqu'ils seront disponibles.",
    },
    "Coming Soon": { "zh-TW": "即將推出", ja: "近日公開", fr: "Bientôt disponible" },
    "Coming soon": { "zh-TW": "即將推出", ja: "近日公開", fr: "Bientôt disponible" },
    "Current Status": { "zh-TW": "目前狀態", ja: "現在の状態", fr: "État actuel" },
    "Desktop software and packaged tools are not published yet. This page will list available installers and user packages when they are ready.": {
      "zh-TW": "桌面軟體與封裝工具尚未發布。可用的安裝程式與使用者套件準備完成後，將列於本頁。",
      ja: "デスクトップソフトウェアとパッケージツールはまだ公開されていません。準備ができ次第、このページに利用可能なインストーラーとユーザーパッケージを掲載します。",
      fr: "Les logiciels de bureau et outils packagés ne sont pas encore publiés. Cette page listera les installateurs et packages utilisateur lorsqu'ils seront prêts.",
    },
    "Planned Packages": { "zh-TW": "規劃套件", ja: "予定パッケージ", fr: "Packages prévus" },
    "Password and credential manager": { "zh-TW": "密碼與憑證管理器", ja: "パスワードと認証情報マネージャー", fr: "Gestionnaire de mots de passe et d'identifiants" },
    "API key manager": { "zh-TW": "API 金鑰管理器", ja: "API キーマネージャー", fr: "Gestionnaire de clés API" },
    "OTP manager": { "zh-TW": "OTP 管理器", ja: "OTP マネージャー", fr: "Gestionnaire OTP" },
    "Device verification utility": { "zh-TW": "裝置驗證工具", ja: "デバイス検証ユーティリティ", fr: "Utilitaire de vérification d'appareil" },
    "OEM-branded custom version": { "zh-TW": "OEM 品牌客製版本", ja: "OEM ブランドのカスタム版", fr: "Version personnalisée à marque OEM" },
    "User-specific deployment package": { "zh-TW": "使用者專屬部署套件", ja: "ユーザー別デプロイパッケージ", fr: "Package de déploiement spécifique utilisateur" },
    "For early access or custom software packaging, contact IIST.": {
      "zh-TW": "如需早期存取或客製軟體封裝，請聯絡 IIST。",
      ja: "早期アクセスまたはカスタムソフトウェアパッケージについては IIST にご連絡ください。",
      fr: "Pour un accès anticipé ou un packaging logiciel personnalisé, contactez IIST.",
    },
    "IIST can quote user-specific packaging, provisioning, and deployment support separately.": {
      "zh-TW": "IIST 可針對使用者專屬封裝、佈建與部署支援另行報價。",
      ja: "IIST はユーザー別のパッケージング、プロビジョニング、デプロイ支援を個別に見積もることができます。",
      fr: "IIST peut chiffrer séparément le packaging, le provisionnement et le support de déploiement spécifiques à l'utilisateur.",
    },
    "Contact IIST for Integration Support": { "zh-TW": "聯絡 IIST 取得整合支援", ja: "統合サポートについて IIST に連絡", fr: "Contacter IIST pour le support d'intégration" },
    "Integration Support": { "zh-TW": "整合支援", ja: "統合サポート", fr: "Support d'intégration" },
    "Need help turning Ankhor functions into a product workflow?": {
      "zh-TW": "需要協助將 Ankhor 功能轉換為產品流程嗎？",
      ja: "Ankhor 機能を製品ワークフローに組み込む支援が必要ですか？",
      fr: "Besoin d'aide pour transformer les fonctions Ankhor en workflow produit ?",
    },
    "Commercial Support": { "zh-TW": "商業支援", ja: "商用サポート", fr: "Support commercial" },
    "Ankhor Key Plus provides a fixed function set. User-specific integration, packaging, testing, and deployment support can be quoted separately.": {
      "zh-TW": "Ankhor Key Plus 提供固定功能集。使用者專屬整合、封裝、測試與部署支援可另行報價。",
      ja: "Ankhor Key Plus は固定の機能セットを提供します。ユーザー別の統合、パッケージング、テスト、デプロイ支援は個別に見積もることができます。",
      fr: "Ankhor Key Plus fournit un ensemble fixe de fonctions. Le support spécifique d'intégration, packaging, test et déploiement peut être chiffré séparément.",
    },
    "IIST Can Help With": { "zh-TW": "IIST 可協助項目", ja: "IIST が支援できる内容", fr: "IIST peut aider avec" },
    "Suggested Email Template": { "zh-TW": "建議電子郵件範本", ja: "推奨メールテンプレート", fr: "Modèle d'e-mail suggéré" },
    "Include the fields below so IIST can evaluate the integration request efficiently.": {
      "zh-TW": "請包含下列欄位，讓 IIST 能有效評估整合需求。",
      ja: "IIST が統合依頼を効率的に評価できるよう、以下の項目を含めてください。",
      fr: "Incluez les champs ci-dessous afin que IIST puisse évaluer efficacement la demande d'intégration.",
    },
    "Connect": { "zh-TW": "連線", ja: "接続", fr: "Connecter" },
    "Disconnect": { "zh-TW": "中斷連線", ja: "切断", fr: "Déconnecter" },
    "Get Info": { "zh-TW": "取得資訊", ja: "情報取得", fr: "Obtenir les infos" },
    "TRNG": { "zh-TW": "TRNG", ja: "TRNG", fr: "TRNG" },
    "Enable Filter": { "zh-TW": "啟用篩選", ja: "フィルターを有効化", fr: "Activer le filtre" },
    "Connected": { "zh-TW": "已連線", ja: "接続済み", fr: "Connecté" },
    "Disconnected": { "zh-TW": "未連線", ja: "未接続", fr: "Déconnecté" },
    "Port opened.": { "zh-TW": "連接埠已開啟。", ja: "ポートを開きました。", fr: "Port ouvert." },
    "Selected port": { "zh-TW": "已選擇連接埠", ja: "選択されたポート", fr: "Port sélectionné" },
    "WebSerial unavailable": { "zh-TW": "WebSerial 無法使用", ja: "WebSerial は利用できません", fr: "WebSerial indisponible" },
    "WebSerial requires https or localhost": { "zh-TW": "WebSerial 需要 https 或 localhost", ja: "WebSerial には https または localhost が必要です", fr: "WebSerial nécessite https ou localhost" },
    "Web browsers does not support USB device connection": {
      "zh-TW": "此瀏覽器不支援 USB 裝置連線",
      ja: "このブラウザは USB デバイス接続に対応していません",
      fr: "Ce navigateur ne prend pas en charge la connexion d'appareils USB",
    },
    "device info failed": { "zh-TW": "裝置資訊失敗", ja: "デバイス情報の取得に失敗しました", fr: "Échec des informations appareil" },
    "device info parse failed": { "zh-TW": "裝置資訊解析失敗", ja: "デバイス情報の解析に失敗しました", fr: "Échec de l'analyse des informations appareil" },
    "device error": { "zh-TW": "裝置錯誤", ja: "デバイスエラー", fr: "Erreur appareil" },
    "disconnected": { "zh-TW": "已中斷連線", ja: "切断されました", fr: "déconnecté" },
    "request already in progress": { "zh-TW": "已有請求進行中", ja: "リクエストはすでに進行中です", fr: "requête déjà en cours" },
    "timeout": { "zh-TW": "逾時", ja: "タイムアウト", fr: "délai expiré" },
    "not connected": { "zh-TW": "尚未連線", ja: "未接続", fr: "non connecté" },
    "ack failed": { "zh-TW": "ACK 失敗", ja: "ACK に失敗しました", fr: "échec ACK" },
    "trng failed": { "zh-TW": "TRNG 失敗", ja: "TRNG に失敗しました", fr: "échec TRNG" },
    "Model": { "zh-TW": "型號", ja: "モデル", fr: "Modèle" },
    "Name": { "zh-TW": "名稱", ja: "名前", fr: "Nom" },
  };

  function getLanguage() {
    const stored = localStorage.getItem(STORAGE_KEY);
    return languageNames[stored] ? stored : DEFAULT_LANGUAGE;
  }

  function t(source, language = getLanguage()) {
    if (language === DEFAULT_LANGUAGE) return source;
    return strings[source]?.[language] || source;
  }

  function translateTextNode(node, language) {
    const source = node.__ankhorSourceText || node.nodeValue;
    if (!source.trim()) return;
    node.__ankhorSourceText = source;
    const translated = source.replace(/\S[\s\S]*\S|\S/, (match) => t(match, language));
    node.nodeValue = translated;
  }

  function translateElementAttributes(element, language) {
    ["title", "aria-label", "alt", "content"].forEach((name) => {
      if (!element.hasAttribute(name)) return;
      element.__ankhorAttrSources = element.__ankhorAttrSources || {};
      const source = element.__ankhorAttrSources[name] || element.getAttribute(name);
      element.__ankhorAttrSources[name] = source;
      element.setAttribute(name, t(source, language));
    });
  }

  function translatePage(language = getLanguage()) {
    document.documentElement.lang = language;
    document.querySelectorAll("title, meta, img, [aria-label], [title]").forEach((element) => {
      translateElementAttributes(element, language);
    });
    if (document.title) {
      const titleSource = document.documentElement.dataset.i18nTitle || document.title;
      document.documentElement.dataset.i18nTitle = titleSource;
      document.title = titleSource
        .split(" | ")
        .map((part) => t(part, language))
        .join(" | ");
    }

    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const parent = node.parentElement;
        if (!parent || parent.closest("script, style, code, pre, textarea")) {
          return NodeFilter.FILTER_REJECT;
        }
        return node.nodeValue.trim() ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      },
    });

    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach((node) => translateTextNode(node, language));
  }

  function setLanguage(language) {
    if (!languageNames[language]) return;
    localStorage.setItem(STORAGE_KEY, language);
    translatePage(language);
    window.dispatchEvent(new CustomEvent("ankhor-language-change", { detail: { language } }));
  }

  function injectSelector() {
    if (document.querySelector(".language-control")) return;
    const control = document.createElement("label");
    control.className = "language-control";

    const label = document.createElement("span");
    label.textContent = "Language";

    const select = document.createElement("select");
    select.setAttribute("aria-label", "Language");
    Object.entries(languageNames).forEach(([value, name]) => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = name;
      select.appendChild(option);
    });
    select.value = getLanguage();
    select.addEventListener("change", () => setLanguage(select.value));

    control.append(label, select);

    const logo = document.querySelector(".site-logo, .tool-logo");
    if (logo?.parentElement) {
      const stack = document.createElement("div");
      stack.className = "language-logo-stack";
      logo.parentElement.insertBefore(stack, logo);
      stack.append(control, logo);
      return;
    }

    document.body.appendChild(control);
  }

  window.AnkhorI18n = {
    languageNames,
    getLanguage,
    setLanguage,
    t,
    translatePage,
  };

  document.addEventListener("DOMContentLoaded", () => {
    injectSelector();
    translatePage();
  });
})();
