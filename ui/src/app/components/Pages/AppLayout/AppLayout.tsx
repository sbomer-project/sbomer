import rhlogo from '../../../../assets/Logo-Red_Hat-A-Standard-RGB.svg';
import { IAppRoute, IAppRouteGroup, routes } from '@app/routes';
import {
  Brand,
  Button,
  Masthead,
  MastheadLogo,
  MastheadMain,
  MastheadToggle, MastheadBrand,
  Nav,
  NavExpandable,
  NavItem,
  NavList,
  Page,
  PageSidebar,
  PageSidebarBody,
  SkipToContent,
  MastheadContent,
  Flex,
  FlexItem,
} from '@patternfly/react-core';
import { BarsIcon } from '@patternfly/react-icons';
import * as React from 'react';
import { Link, NavLink, useLocation } from 'react-router-dom';

interface IAppLayout {
  children: React.ReactNode;
}

const AppLayout: React.FunctionComponent<IAppLayout> = ({ children }) => {
  const [sidebarOpen, setSidebarOpen] = React.useState(true);
  const Header = (
    <Masthead>

      <MastheadMain><MastheadToggle>
        <Button icon={<BarsIcon />} variant="plain" onClick={() => setSidebarOpen(!sidebarOpen)} aria-label="Global navigation" />
      </MastheadToggle>
        <MastheadBrand data-codemods><MastheadLogo data-codemods component="a">
          <Link to="/"><Brand src={rhlogo} alt="Red Hat" widths={{ default: '150px' }} /></Link>
        </MastheadLogo></MastheadBrand>
      </MastheadMain>
      <MastheadContent>
        <Flex style={{ marginLeft: 'auto', alignItems: 'center', gap: '1rem' }}>
          <FlexItem>
            <span style={{ fontWeight: 'bold', fontSize: '1.1rem', letterSpacing: '1px' }}>
              SBOMER CLASSIC
            </span>
          </FlexItem>
        </Flex>
      </MastheadContent>
    </Masthead>
  );

  const location = useLocation();

  const renderNavItem = (route: IAppRoute, index: number) => (
    <NavItem key={`${route.label}-${index}`} id={`${route.label}-${index}`} isActive={route.path === location.pathname}>
      <NavLink to={route.path}>
        {route.label}
      </NavLink>
    </NavItem>
  );

  const renderNavGroup = (group: IAppRouteGroup, groupIndex: number) => (
    <NavExpandable
      key={`${group.label}-${groupIndex}`}
      id={`${group.label}-${groupIndex}`}
      title={group.label}
      isActive={group.routes.some((route) => route.path === location.pathname)}
    >
      {group.routes.map((route, idx) => route.label && renderNavItem(route, idx))}
    </NavExpandable>
  );

  const Navigation = (
    <Nav id="nav-primary-simple">
      <NavList id="nav-list-simple">
        {routes.map(
          (route, idx) => route.label && (!route.routes ? renderNavItem(route, idx) : renderNavGroup(route, idx)),
        )}
      </NavList>
    </Nav>
  );

  const Sidebar = (
    <PageSidebar>
      <PageSidebarBody>{Navigation}</PageSidebarBody>
    </PageSidebar>
  );

  const pageId = 'primary-app-container';

  const PageSkipToContent = (
    <SkipToContent
      onClick={(event) => {
        event.preventDefault();
        const primaryContentContainer = document.getElementById(pageId);
        primaryContentContainer && primaryContentContainer.focus();
      }}
      href={`#${pageId}`}
    >
      Skip to Content
    </SkipToContent>
  );
  return (
    <Page mainContainerId={pageId} masthead={Header} sidebar={sidebarOpen && Sidebar} skipToContent={PageSkipToContent}>
      {children}
    </Page>
  );
};

export { AppLayout };
