import { Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { HomePage } from "./pages/HomePage";
import { LouvrePage } from "./pages/LouvrePage";
import { EiffelPage } from "./pages/EiffelPage";
import { SeinePage } from "./pages/SeinePage";
import { MontmartrePage } from "./pages/MontmartrePage";

export const App = () => {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/louvre" element={<LouvrePage />} />
        <Route path="/eiffel" element={<EiffelPage />} />
        <Route path="/seine" element={<SeinePage />} />
        <Route path="/montmartre" element={<MontmartrePage />} />
      </Routes>
    </Layout>
  );
};
