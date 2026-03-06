export const HomePage = () => {
  return (
    <section className="page">
      <div className="grid two-columns">
        <div>
          <h1 className="title">讓你的品牌，住進巴黎的記憶裡</h1>
          <p className="lead">
            我們結合巴黎地標場景、城市氣味與聲音敘事，為品牌打造沉浸式的行銷企劃，讓每一次活動都成為旅人相機裡的一張風景。
          </p>
          <div className="highlights">
            <div className="badge">品牌沉浸體驗</div>
            <div className="badge">城市故事腳本</div>
            <div className="badge">線上線下整合</div>
          </div>
        </div>
        <div className="card">
          <h2>巴黎三大主題提案</h2>
          <ul className="list">
            <li>
              <span className="list-title">羅浮宮 · 藝術策展行銷</span>
              <span className="list-desc">把你的產品變成展品，讓觀眾像看藝術品一樣閱讀品牌。</span>
            </li>
            <li>
              <span className="list-title">艾菲爾鐵塔 · 夜間品牌秀</span>
              <span className="list-desc">結合燈光、聲音與社群即時互動，打造只屬於你的夜色記憶點。</span>
            </li>
            <li>
              <span className="list-title">塞納河 · 流動式內容體驗</span>
              <span className="list-desc">讓品牌跟著河流移動，把觸及變成一趟旅程。</span>
            </li>
          </ul>
        </div>
      </div>
    </section>
  );
};
