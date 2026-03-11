export const MontmartrePage = () => {
  return (
    <section className="page">
      <h1 className="title">蒙馬特 · 街區故事與品牌個性</h1>
      <p className="lead">
        蒙馬特不是完美對稱的明信片，而是一個充滿轉角與手寫標語的街區。我們把這種「不那麼制式」的氣氛，轉譯成有溫度又有個性的品牌表達。
      </p>
      <div className="grid two-columns">
        <div className="card">
          <h2>適合的品牌氣質</h2>
          <ul className="list">
            <li>
              <span className="list-title">生活風格與選物品牌</span>
              <span className="list-desc">用故事與日常感堆疊出品牌的獨特氣味。</span>
            </li>
            <li>
              <span className="list-title">咖啡館、餐飲與小店</span>
              <span className="list-desc">把店內的細節變成可以被記住的內容素材。</span>
            </li>
            <li>
              <span className="list-title">創作者與獨立品牌</span>
              <span className="list-desc">讓個人風格變成品牌資產，而不是風險。</span>
            </li>
          </ul>
        </div>
        <div className="card">
          <h2>可以做的行銷企劃</h2>
          <ul className="list">
            <li>
              <span className="list-title">街區導覽式品牌體驗</span>
            </li>
            <li>
              <span className="list-title">手寫風格視覺與招牌設計</span>
            </li>
            <li>
              <span className="list-title">在地合作與快閃活動策劃</span>
            </li>
          </ul>
        </div>
      </div>
    </section>
  );
};

