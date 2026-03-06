export const LouvrePage = () => {
  return (
    <section className="page">
      <h1 className="title">羅浮宮 · 藝術級品牌敘事</h1>
      <p className="lead">
        從《蒙娜麗莎》的微笑到玻璃金字塔的倒影，我們把經典藝術語彙轉譯成品牌內容語言，為你打造一場高質感的藝術行銷展。
      </p>
      <div className="grid two-columns">
        <div className="card">
          <h2>適合的品牌類型</h2>
          <ul className="list">
            <li>
              <span className="list-title">精品 & 設計品牌</span>
              <span className="list-desc">以策展視角呈現產品細節與品牌故事。</span>
            </li>
            <li>
              <span className="list-title">文化內容 / 平台</span>
              <span className="list-desc">把內容策展搬進真實空間，創造深度互動。</span>
            </li>
            <li>
              <span className="list-title">高單價服務</span>
              <span className="list-desc">透過藝術氛圍強化信任感與專業度。</span>
            </li>
          </ul>
        </div>
        <div className="card">
          <h2>可執行的行銷元素</h2>
          <ul className="list">
            <li>
              <span className="list-title">沉浸式展覽動線設計</span>
            </li>
            <li>
              <span className="list-title">作品式產品拍攝 & 形象影片</span>
            </li>
            <li>
              <span className="list-title">VIP 導覽活動與閉門體驗</span>
            </li>
          </ul>
        </div>
      </div>
    </section>
  );
};
