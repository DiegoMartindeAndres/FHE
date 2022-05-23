import React from "react";
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import PageOne from "./routes/linearReg";
import PageTwo from "./routes/encryptedDb";
import "./style/navbar.css";
import { ReactComponent as PageOneIcon } from './res/pageoneicon.svg';
import { ReactComponent as PageTwoIcon } from './res/pagetwoicon.svg';

function App() {

  return (
    <BrowserRouter>
      <nav className="nav">
        <ul className="nav__menu">
          <li className="nav__item">
            <NavLink to="/" className="nav__link">
              <PageOneIcon title="Cálculo predictivo"/>
            </NavLink>
          </li>
          <li className="nav__item">
            <NavLink to="/persist" className="nav__link">
              <PageTwoIcon title="Persistencia de datos"/>
            </NavLink>
          </li>
        </ul>
      </nav>
      <div style={{marginTop: '75px', padding: '1%'}}>
        <Routes>
          <Route path='/' element={<PageOne/>}/>
          <Route path='/persist' element={<PageTwo/>}/>
        </Routes>
      </div>
    </BrowserRouter>
  )
  
}

export default App;
